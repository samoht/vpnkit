open Lwt.Infix

let src =
  let src = Logs.Src.create "test" ~doc:"Test the slirp stack" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Dns_policy = struct
  let config_of_ips ips =
    let open Dns_forward.Config in
    let servers =
      Server.Set.of_list (
        List.map (fun (ip, _) ->
            { Server.address = { Address.ip; port = 53 };
              zones = Domain.Set.empty;
              timeout_ms = Some 2000; order = 0 }
          ) ips)
    in
    { servers; search = []; assume_offline_after_drops = None }

  module Config = Hostnet_dns.Config

  let google_dns =
    let ips = [
      Ipaddr.of_string_exn "8.8.8.8", 53;
      Ipaddr.of_string_exn "8.8.4.4", 53;
    ] in
    `Upstream (config_of_ips ips)

  type priority = int

  module IntMap =
    Map.Make(struct
      type t = int let
      compare (a: int) (b: int) = Pervasives.compare a b
    end)

  let t = ref (IntMap.add 0 google_dns IntMap.empty)

  let config () =
    snd @@ IntMap.max_binding !t

  let add ~priority ~config:c =
    let before = config () in
    t := IntMap.add priority c (!t);
    let after = config () in
    if Config.compare before after <> 0
    then Log.info (fun f ->
        f "Add(%d): DNS configuration changed to: %a" priority Config.pp after)

  let remove ~priority =
    let before = config () in
    t := IntMap.remove priority !t;
    let after = config () in
    if Config.compare before after <> 0
    then Log.info (fun f ->
        f "Remove(%d): DNS configuration changed to: %a" priority
          Config.pp after)

end

module Make(Host: Sig.HOST) = struct
  module VMNET = Vmnet.Make(Host.Sockets.Stream.Tcp)
  module Config = Active_config.Make(Host.Time)(Host.Sockets.Stream.Unix)
  module Vnet = Basic_backend.Make
  module Slirp_stack =
    Slirp.Make(Config)(VMNET)(Dns_policy)(Mclock)(Stdlibrandom)(Host)(Vnet)

  module Client = struct
    module Netif = VMNET
    module Ethif1 = Ethif.Make(Netif)
    module Arpv41 = Arpv4.Make(Ethif1)(Mclock)(Host.Time)
    module Ipv41 = Static_ipv4.Make(Ethif1)(Arpv41)
    module Icmpv41 = Icmpv4.Make(Ipv41)
    module Udp1 = Udp.Make(Ipv41)(Stdlibrandom)
    module Tcp1 = Tcp.Flow.Make(Ipv41)(Host.Time)(Mclock)(Stdlibrandom)
    include Tcpip_stack_direct.Make(Host.Time)
        (Stdlibrandom)(Netif)(Ethif1)(Arpv41)(Ipv41)(Icmpv41)(Udp1)(Tcp1)

    let or_error name m =
      m >>= function
      | `Error _ -> Fmt.kstrf failwith "Failed to connect %s device" name
      | `Ok x    -> Lwt.return x

    let connect (interface: VMNET.t) =
      Ethif1.connect interface >>= fun ethif ->
      Mclock.connect () >>= fun clock ->
      Arpv41.connect ethif clock >>= fun arp ->
      Ipv41.connect ethif arp >>= fun ipv4 ->
      Icmpv41.connect ipv4 >>= fun icmpv4 ->
      Udp1.connect ipv4 >>= fun udp4 ->
      Tcp1.connect ipv4 clock >>= fun tcp4 ->
      let cfg = {
        Mirage_stack_lwt.name = "stackv4_ip";
        interface;
      } in
      connect cfg ethif arp ipv4 icmpv4 udp4 tcp4
      >>= fun stack ->
      Lwt.return stack
  end

  module DNS = Dns_resolver_mirage.Make(Host.Time)(Client)

  let primary_dns_ip = Ipaddr.V4.of_string_exn "192.168.65.1"

  let extra_dns_ip = List.map Ipaddr.V4.of_string_exn [
      "192.168.65.3"; "192.168.65.4"; "192.168.65.5"; "192.168.65.6";
      "192.168.65.7"; "192.168.65.8"; "192.168.65.9"; "192.168.65.10";
    ]

  let peer_ip = Ipaddr.V4.of_string_exn "192.168.65.2"
  let local_ip = Ipaddr.V4.of_string_exn "192.168.65.1"
  let highest_ip = Ipaddr.V4.of_string_exn "192.168.65.254"
  let server_macaddr = Slirp.default_server_macaddr

  let global_arp_table : Slirp.arp_table =
    { Slirp.mutex = Lwt_mutex.create ();
      table = [(local_ip, Slirp.default_server_macaddr)]
    }

  let client_uuids : Slirp.uuid_table =
    { Slirp.mutex = Lwt_mutex.create ();
      table = Hashtbl.create 50;
    }

  let config_without_bridge =
    Mclock.connect () >|= fun clock ->
    {
      Slirp.peer_ip;
      local_ip;
      highest_ip;
      extra_dns_ip;
      server_macaddr;
      get_domain_search = (fun () -> []);
      get_domain_name = (fun () -> "local");
      client_uuids;
      bridge_connections = false;
      global_arp_table;
      mtu = 1500;
      host_names = [];
      clock;
    }

  (* This is a hacky way to get a hancle to the server side of the stack. *)
  let slirp_stack = ref None
  let slirp_stack_c = Lwt_condition.create ()

  let rec get_slirp_stack () =
    match !slirp_stack with
    | None   -> Lwt_condition.wait slirp_stack_c >>= get_slirp_stack
    | Some x -> Lwt.return x

  let set_slirp_stack c =
    slirp_stack := Some c;
    Lwt_condition.signal slirp_stack_c ()

  let start_stack l2_switch config () =
    Host.Sockets.Stream.Tcp.bind (Ipaddr.V4 Ipaddr.V4.localhost, 0)
    >|= fun server ->
    let _, port = Host.Sockets.Stream.Tcp.getsockname server in
    Host.Sockets.Stream.Tcp.listen server (fun flow ->
        Slirp_stack.connect config flow l2_switch >>= fun stack ->
        set_slirp_stack stack;
        Log.info (fun f -> f "stack connected");
        Slirp_stack.after_disconnect stack >|= fun () ->
        Log.info (fun f -> f "stack disconnected")
      );
    port

  let connection =
    config_without_bridge >>= fun config ->
    start_stack (Vnet.create ()) config ()

  let with_stack f =
    connection >>= fun port ->
    Host.Sockets.Stream.Tcp.connect (Ipaddr.V4 Ipaddr.V4.localhost, port)
    >>= function
    | Error (`Msg x) -> failwith x
    | Ok flow ->
      Log.info (fun f -> f "Made a loopback connection");
      let client_macaddr = Slirp.default_client_macaddr in
      let uuid =
        match Uuidm.of_string "d1d9cd61-d0dc-4715-9bb3-4c11da7ad7a5" with
        | Some x -> x
        | None -> failwith "unable to parse test uuid"
      in
      VMNET.client_of_fd ~uuid ~server_macaddr:client_macaddr flow
      >>= function
      | Error (`Msg x ) ->
        (* Server will close when it gets EOF *)
        Host.Sockets.Stream.Tcp.close flow >>= fun () ->
        failwith x
      | Ok client' ->
        Lwt.finalize (fun () ->
            Log.info (fun f -> f "Initialising client TCP/IP stack");
            Client.connect client' >>= fun client ->
            get_slirp_stack () >>= fun slirp_stack ->
            f slirp_stack client
          ) (fun () ->
            (* Server will close when it gets EOF *)
            VMNET.disconnect client'
          )
end
