%%%-------------------------------------------------------------------
%%% @doc Verification of Handshake Logic
%%% @end
%%%-------------------------------------------------------------------
-module(nquic_handshake_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("nquic_frame.hrl").
-include("nquic_packet.hrl").
-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([server_handshake_flight_test/1, full_handshake_test/1]).

all() -> [server_handshake_flight_test, full_handshake_test].

init_per_suite(Config) ->
    ssl:start(),
    application:ensure_all_started(crypto),
    ok = nquic_test_util:ensure_test_certs(conf_dir()),
    Config.

end_per_suite(_Config) ->
    ok.

conf_dir() ->
    SrcFile = code:which(?MODULE),
    ProjectRoot = find_project_root(filename:dirname(SrcFile)),
    filename:join([ProjectRoot, "test", "conf"]).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true -> Dir;
        false -> find_project_root(filename:dirname(Dir))
    end.

full_handshake_test(_Config) ->
    {ok, ServerSock} = nquic_socket:open(#{}),
    {ok, SPort} = nquic_socket:port(ServerSock),
    {ok, ClientSock} = nquic_socket:open(#{}),

    ServerPeer = nquic_socket:make_sockaddr({127, 0, 0, 1}, SPort),

    process_flag(trap_exit, true),

    {ok, SPid} = nquic_conn_statem:start_link(#{
        role => server,
        socket => ServerSock,
        owner => self(),
        certfile => "../../../../test/conf/server.pem",
        keyfile => "../../../../test/conf/server.key"
    }),
    ok = nquic_socket:controlling_process(ServerSock, SPid),

    {ok, CPid} = nquic_conn_statem:start_link(#{
        role => client,
        socket => ClientSock,
        peer => ServerPeer,
        owner => self()
    }),
    ok = nquic_socket:controlling_process(ClientSock, CPid),

    ok = wait_export(CPid, 5000),
    ok = wait_export(SPid, 5000),

    false = is_process_alive(CPid),
    false = is_process_alive(SPid),
    _ = nquic_socket:close(ServerSock),
    _ = nquic_socket:close(ClientSock),
    ok.

wait_export(Pid, Timeout) ->
    receive
        {nquic_conn_export, Pid, {ok, _State, _Socket, undefined}} -> ok
    after Timeout ->
        ct:fail({export_timeout, Pid})
    end.

server_handshake_flight_test(_Config) ->
    {ok, ServerSock} = nquic_socket:open(#{}),
    {ok, Port} = nquic_socket:port(ServerSock),
    {ok, ClientSock} = nquic_socket:open(#{}),

    ServerPeer = nquic_socket:make_sockaddr({127, 0, 0, 1}, Port),

    {ok, ClientPid} = nquic_conn_statem:start_link(#{
        role => client,
        peer => ServerPeer,
        socket => ClientSock
    }),

    timer:sleep(50),
    {ok, {ClientAddr, Packet}} = recv_with_retry(ServerSock, 10),
    ClientPeer = ClientAddr,

    {ok, Header, Rest} = nquic_packet:parse_header(Packet),
    #long_header{dcid = DCID, scid = SCID} = Header,

    {CSecret, SSecret} = nquic_keys:initial_secrets(DCID),
    Keys = #{
        key => element(1, nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1)),
        iv => element(2, nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1)),
        hp => element(3, nquic_keys:derive_packet_protection(CSecret, aes_128_gcm, 1))
    },

    {ok, _DecHeader, Frames} = nquic_packet:unmask_and_decrypt(
        Packet, Rest, Header, aes_128_gcm, Keys, 0
    ),

    [#crypto{data = ClientHello}] = [F || F <- Frames, is_record(F, crypto)],

    {_PrivKey, PubKey} = crypto:generate_key(ecdh, x25519),
    ServerHelloBin = make_server_hello(PubKey),

    Transcript0 = <<ClientHello/binary, ServerHelloBin/binary>>,
    TranscriptHash0 = crypto:hash(sha256, Transcript0),

    ClientShare = parse_client_hello_share(ClientHello),

    SharedSecretReal = crypto:compute_key(ecdh, ClientShare, _PrivKey, x25519),
    {_ClientHSSecret, ServerHSSecret, _HandshakeSecret} = nquic_keys:handshake_secrets(
        SharedSecretReal, TranscriptHash0
    ),

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

    EE = <<8, 0, 0, 2, 0, 0>>,

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

    timer:sleep(50),
    ok = nquic_socket:send(ServerSock, ClientPeer, Masked2),

    timer:sleep(100),
    ?assert(is_process_alive(ClientPid)),

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
    ExtVer = <<0, 43, 2, 3, 4>>,
    KeyShareData = <<0, 29, 0, 32, PubKey/binary>>,
    ExtKeyShare = <<0, 51, (byte_size(KeyShareData)):16, KeyShareData/binary>>,
    Extensions = <<ExtVer/binary, ExtKeyShare/binary>>,
    Body =
        <<LegacyVer/binary, Random/binary, 32, (binary:copy(<<0>>, 32))/binary, CipherSuite/binary,
            CompMethod, (byte_size(Extensions)):16, Extensions/binary>>,
    Header = <<2, (byte_size(Body)):24>>,
    <<Header/binary, Body/binary>>.
