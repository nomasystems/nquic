%%%-------------------------------------------------------------------
%%% @doc Stream Integration Tests
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_stream_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-include("nquic_transport.hrl").
-compile([export_all, nowarn_export_all]).

all() -> [stream_send_test].

init_per_suite(Config) ->
    ssl:start(),
    application:ensure_all_started(crypto),
    Config.

end_per_suite(_Config) ->
    ssl:stop(),
    ok.

stream_send_test(_Config) ->
    {ok, ServerSock} = nquic_socket:open(#{}),
    {ok, Port} = nquic_socket:port(ServerSock),
    {ok, ClientSock} = nquic_socket:open(#{}),

    ServerPeer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),

    process_flag(trap_exit, true),

    {ok, ClientPid} = nquic_conn_statem:start_link(#{
        role => client,
        peer => ServerPeer,
        socket => ClientSock,
        owner => self()
    }),
    ok = nquic_socket:controlling_process(ClientSock, ClientPid),

    timer:sleep(50),
    {ok, {ClientAddr, InitialPkt}} = recv_with_retry(ServerSock, 10),
    ClientPeer = ClientAddr,

    {ok, Header, Rest} = nquic_packet:parse_header(InitialPkt),
    #long_header{dcid = DCID, scid = SCID} = Header,

    {CSecret, SSecret} = nquic_keys:initial_secrets(DCID),
    Keys = #{
        key => element(1, nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1)),
        iv => element(2, nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1)),
        hp => element(3, nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1))
    },
    {ok, _, Frames} = nquic_packet:unmask_and_decrypt(
        InitialPkt, Rest, Header, aes_128_gcm, Keys, 0
    ),
    [#crypto{data = ClientHello}] = [F || F <- Frames, is_record(F, crypto)],

    {PubKey, PrivKey} = crypto:generate_key(ecdh, x25519),
    ServerHelloBin = make_server_hello(PubKey),

    CryptoFrame1 = #crypto{offset = 0, data = ServerHelloBin},
    Payload1 = iolist_to_binary(nquic_frame:encode(CryptoFrame1)),
    {SKey, SIV, SHP} = nquic_keys:derive_packet_protection(SSecret, aes_128_gcm, 1),
    ServerHeader = #long_header{
        type = initial,
        version = 1,
        dcid = SCID,
        scid = DCID,
        token = <<>>,
        payload_len = byte_size(Payload1) + 16,
        packet_number = 0
    },
    ServerHeaderBin = nquic_packet:encode_header(ServerHeader),
    PnOffset1 = byte_size(ServerHeaderBin) - 4,
    {Ctx1, Tag1} = nquic_crypto:encrypt(aes_128_gcm, SKey, SIV, 0, ServerHeaderBin, Payload1),
    FP1 = <<ServerHeaderBin/binary, Ctx1/binary, Tag1/binary>>,
    Masked1 = nquic_hp:mask(aes_128_gcm, SHP, binary:part(FP1, 4 + PnOffset1, 16), FP1, PnOffset1),
    ok = nquic_socket:send(ServerSock, ClientPeer, Masked1),

    ClientShare = parse_client_hello_share(ClientHello),

    Transcript0 = <<ClientHello/binary, ServerHelloBin/binary>>,
    TranscriptHash0 = crypto:hash(sha256, Transcript0),
    SharedSecretReal = crypto:compute_key(ecdh, ClientShare, PrivKey, x25519),

    {_, ServerHSSecret, _HandshakeSecret} = nquic_keys:handshake_secrets(
        SharedSecretReal, TranscriptHash0
    ),
    ct:pal("Test ServerHSSecret: ~p", [ServerHSSecret]),

    Params = #transport_params{
        initial_max_data = 10000,
        initial_max_stream_data_bidi_remote = 10000,
        initial_max_streams_bidi = 10,
        initial_source_connection_id = DCID
    },
    TPBin = nquic_transport:encode(Params),
    ExtTP = <<57:16, (byte_size(TPBin)):16, TPBin/binary>>,
    Exts = ExtTP,
    ExtLen = byte_size(Exts),
    EEBody = <<ExtLen:16, Exts/binary>>,
    EELen = byte_size(EEBody),
    EE = <<8, EELen:24, EEBody/binary>>,

    Transcript1 = <<Transcript0/binary, EE/binary>>,
    FinishedKey = nquic_keys:qhkdf_expand(ServerHSSecret, <<"finished">>, <<>>, 32),
    TranscriptHash1 = crypto:hash(sha256, Transcript1),
    VerifyData = crypto:mac(hmac, sha256, FinishedKey, TranscriptHash1),
    Fin = <<20, 0, 0, 32, VerifyData/binary>>,

    HandshakePayload = <<EE/binary, Fin/binary>>,
    CryptoFrame2 = #crypto{offset = 0, data = HandshakePayload},
    Payload2 = iolist_to_binary(nquic_frame:encode(CryptoFrame2)),
    {HS_SKey, HS_SIV, HS_SHP} = nquic_keys:derive_packet_protection(ServerHSSecret, aes_128_gcm, 1),
    HandshakeHeader = #long_header{
        type = handshake,
        version = 1,
        dcid = SCID,
        scid = DCID,
        payload_len = byte_size(Payload2) + 16,
        packet_number = 0
    },
    HandshakeHeaderBin = nquic_packet:encode_header(HandshakeHeader),
    PnOffset2 = byte_size(HandshakeHeaderBin) - 4,
    {Ctx2, Tag2} = nquic_crypto:encrypt(
        aes_128_gcm, HS_SKey, HS_SIV, 0, HandshakeHeaderBin, Payload2
    ),
    FP2 = <<HandshakeHeaderBin/binary, Ctx2/binary, Tag2/binary>>,
    Masked2 = nquic_hp:mask(
        aes_128_gcm, HS_SHP, binary:part(FP2, 4 + PnOffset2, 16), FP2, PnOffset2
    ),
    ok = nquic_socket:send(ServerSock, ClientPeer, Masked2),

    timer:sleep(100),

    {ok, {_, FinPkt}} = recv_with_retry(ServerSock, 10),

    <<1:1, _/bitstring>> = FinPkt,

    receive
        {nquic_conn_export, ClientPid, {ok, _, _, undefined}} -> ok
    after 5000 -> ct:fail(client_export_timeout)
    end,
    false = is_process_alive(ClientPid),

    _ = nquic_socket:close(ServerSock),
    ok.

recv_with_retry(_Socket, 0) ->
    {error, timeout};
recv_with_retry(Socket, Retries) ->
    case nquic_socket:recv_now(Socket) of
        {ok, Result} ->
            {ok, Result};
        {select, _} ->
            timer:sleep(100),
            recv_with_retry(Socket, Retries - 1);
        Error ->
            Error
    end.

parse_client_hello_share(ClientHello) ->
    <<1, _Len:24, _Ver:2/binary, _Random:32/binary, Rest1/binary>> = ClientHello,
    {_, Rest2} = parse_vec8(Rest1),
    {_, Rest3} = parse_vec16(Rest2),
    {_, Rest4} = parse_vec8(Rest3),
    <<ExtLen:16, ExtData:ExtLen/binary>> = Rest4,
    find_share_in_ext(ExtData).

find_share_in_ext(<<>>) ->
    throw(share_not_found);
find_share_in_ext(<<Type:16, Len:16, Val:Len/binary, Rest/binary>>) ->
    case Type of
        16#0033 ->
            <<_VecLen:16, Shares/binary>> = Val,
            find_share_entry(Shares);
        _ ->
            find_share_in_ext(Rest)
    end.

find_share_entry(<<Group:16, KLen:16, Key:KLen/binary, Rest/binary>>) ->
    case Group of
        16#001d -> Key;
        _ -> find_share_entry(Rest)
    end;
find_share_entry(<<>>) ->
    throw(share_not_found).

parse_vec8(<<Len:8, Data:Len/binary, Rest/binary>>) -> {Data, Rest}.
parse_vec16(<<Len:16, Data:Len/binary, Rest/binary>>) -> {Data, Rest}.

make_server_hello(PubKey) ->
    LegacyVer = <<3, 3>>,
    Random = crypto:strong_rand_bytes(32),
    CipherSuite = <<19, 1>>,
    CompMethod = 0,
    ExtVer = <<0, 43, 0, 2, 3, 4>>,
    KeyShareData = <<0, 29, 0, 32, PubKey/binary>>,
    ExtKeyShare = <<0, 51, (byte_size(KeyShareData)):16, KeyShareData/binary>>,
    Extensions = <<ExtVer/binary, ExtKeyShare/binary>>,
    Body =
        <<LegacyVer/binary, Random/binary, 32, (binary:copy(<<0>>, 32))/binary, CipherSuite/binary,
            CompMethod, (byte_size(Extensions)):16, Extensions/binary>>,
    Header = <<2, (byte_size(Body)):24>>,
    <<Header/binary, Body/binary>>.
