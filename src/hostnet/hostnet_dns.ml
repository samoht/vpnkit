open Lwt.Infix

let src =
  let src = Logs.Src.create "dns" ~doc:"Resolve DNS queries on the host" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Config = struct
  type t = [
    | `Upstream of Dns_forward.Config.t
    | `Host
  ]

  let pp ppf = function
  | `Upstream x ->
    Fmt.pf ppf "use upstream DNS servers %s" (Dns_forward.Config.to_string x)
  | `Host -> Fmt.string ppf "use host resolver"

  let compare a b = match a, b with
  | `Upstream x, `Upstream y -> Dns_forward.Config.compare x y
  | `Host, `Upstream _ -> -1
  | `Upstream _, `Host -> 1
  | `Host, `Host -> 0
end


module Policy(Files: Sig.FILES) = struct
  let config_of_ips ips =
    let open Dns_forward.Config in
    let servers = Server.Set.of_list (
        List.map (fun (ip, _) ->
            { Server.address = { Address.ip; port = 53 }; zones = Domain.Set.empty;
              timeout_ms = Some 2000; order = 0 }
          ) ips) in
    { servers; search = []; assume_offline_after_drops = None }

  module IntMap =
    Map.Make(struct
      type t = int
      let compare (a: int) (b: int) = Pervasives.compare a b
    end)

  let google_dns =
    let ips = [
      Ipaddr.of_string_exn "8.8.8.8", 53;
      Ipaddr.of_string_exn "8.8.4.4", 53;
    ] in
    `Upstream (config_of_ips ips)

  type priority = int

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
    then
      Log.info (fun f ->
          f "Remove(%d): DNS configuration changed to: %a" priority
            Config.pp after)

  (* Watch for the /etc/resolv.file *)
  let resolv_conf = "/etc/resolv.conf"
  let () =
    match Files.watch_file resolv_conf (fun () ->
        Lwt.async (fun () ->
            let open Lwt_result.Infix in
            Files.read_file resolv_conf >|= fun txt ->
            match Dns_forward.Config.Unix.of_resolv_conf txt with
            | Error (`Msg m) ->
              Log.err (fun f -> f "Failed to parse %s: %s" resolv_conf m)
            | Ok servers ->
              add ~priority:2 ~config:(`Upstream servers)
          )
      ) with
    | Error (`Msg m) ->
      Log.info (fun f -> f "Cannot watch %s: %s" resolv_conf m)
    | Ok _watch ->
      Log.info (fun f -> f "Will watch %s for changes" resolv_conf)

end

let try_etc_hosts =
  let open Dns.Packet in
  function
  | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
    begin
      match List.fold_left (fun found (name, ip) ->
          match found, ip with
          | Some v4, _           -> Some v4
          | None,   Ipaddr.V4 v4 ->
            if Dns.Name.to_string q_name = name then Some v4 else None
          | None,   Ipaddr.V6 _  -> None
        ) None !(Hosts.etc_hosts)
      with
      | None -> None
      | Some v4 ->
        Log.info (fun f ->
            f "DNS: %s is %a in in /etc/hosts" (Dns.Name.to_string q_name)
              Ipaddr.V4.pp_hum v4);
        Some [ { name = q_name; cls = RR_IN;
                 flush = false; ttl = 0l; rdata = A v4 } ]
    end
  | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
    begin
      match List.fold_left (fun found (name, ip) -> match found, ip with
        | Some v6, _           -> Some v6
        | None,   Ipaddr.V6 v6 ->
          if Dns.Name.to_string q_name = name then Some v6 else None
        | None,   Ipaddr.V4 _  -> None
        ) None !(Hosts.etc_hosts)
      with
      | None -> None
      | Some v6 ->
        Log.info (fun f ->
            f "DNS: %s is %a in in /etc/hosts" (Dns.Name.to_string q_name)
              Ipaddr.V6.pp_hum v6);
        Some [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l;
                 rdata = AAAA v6 } ]
    end
  | _ -> None

let try_builtins local_ip host_names question =
  let open Dns.Packet in
  match local_ip, question with
  | Ipaddr.V4 local_ip, { q_class = Q_IN; q_type = (Q_A|Q_AAAA); q_name; _ }
    when List.mem q_name host_names ->
    Log.info (fun f ->
        f "DNS: %s is a builtin: %a" (Dns.Name.to_string q_name)
          Ipaddr.V4.pp_hum local_ip);
    Some [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l;
             rdata = A local_ip } ]
  | _ -> None

module Make
    (Ip: Mirage_protocols_lwt.IPV4)
    (Udp:Mirage_protocols_lwt.UDPV4)
    (Tcp:Mirage_protocols_lwt.TCPV4)
    (Socket: Sig.SOCKETS)
    (D: Sig.DNS)
    (Time: Mirage_time_lwt.S)
    (Clock: Mirage_clock_lwt.MCLOCK)
    (Recorder: Sig.RECORDER) =
struct

  (* DNS uses slightly different protocols over TCP and UDP. We need
     both a UDP and TCP resolver configured to use the upstream
     servers. We will map UDP onto UDP and TCP onto TCP, leaving the
     client to handle the truncated bit and retransmissions. *)

  module Dns_tcp_client =
    Dns_forward.Rpc.Client.Make(Socket.Stream.Tcp)
      (Dns_forward.Framing.Tcp(Socket.Stream.Tcp))(Time)

  module Dns_tcp_resolver =
    Dns_forward.Resolver.Make(Dns_tcp_client)(Time)(Clock)

  module Dns_udp_client =
    Dns_forward.Rpc.Client.Make(Socket.Datagram.Udp)
      (Dns_forward.Framing.Udp(Socket.Datagram.Udp))(Time)

  module Dns_udp_resolver =
    Dns_forward.Resolver.Make(Dns_udp_client)(Time)(Clock)

  (* We need to be able to parse the incoming framed TCP messages *)
  module Dns_tcp_framing = Dns_forward.Framing.Tcp(Tcp)

  type dns = {
    dns_tcp_resolver: Dns_tcp_resolver.t;
    dns_udp_resolver: Dns_udp_resolver.t;
  }

  type resolver =
    | Upstream of dns (* use upstream DNS servers *)
    | Host (* use the host resolver *)

  type t = {
    local_ip: Ipaddr.t;
    host_names: Dns.Name.t list;
    resolver: resolver;
  }

  let recorder = ref None
  let set_recorder r = recorder := Some r

  let destroy = function
  | { resolver = Upstream { dns_tcp_resolver; dns_udp_resolver; _ }; _ } ->
    Dns_tcp_resolver.destroy dns_tcp_resolver
    >>= fun () ->
    Dns_udp_resolver.destroy dns_udp_resolver
  | { resolver = Host; _ } ->
    Lwt.return_unit

  let record_udp ~source_ip ~source_port ~dest_ip ~dest_port bufs =
    match !recorder with
    | Some recorder ->
      (* This is from mirage-tcpip-- ideally we would use a simpler
         packet creation fn *)
      let frame = Io_page.to_cstruct (Io_page.get 1) in
      let smac = "\000\000\000\000\000\000" in
      Ethif_wire.set_ethernet_src smac 0 frame;
      Ethif_wire.set_ethernet_ethertype frame 0x0800;
      let buf = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
      Ipv4_wire.set_ipv4_hlen_version buf ((4 lsl 4) + (5));
      Ipv4_wire.set_ipv4_tos buf 0;
      Ipv4_wire.set_ipv4_ttl buf 38;
      let proto = Ipv4_packet.Marshal.protocol_to_int `UDP in
      Ipv4_wire.set_ipv4_proto buf proto;
      Ipv4_wire.set_ipv4_src buf (Ipaddr.V4.to_int32 source_ip);
      Ipv4_wire.set_ipv4_dst buf (Ipaddr.V4.to_int32 dest_ip);
      let header_len =
        Ethif_wire.sizeof_ethernet + Ipv4_wire.sizeof_ipv4
      in

      let frame = Cstruct.set_len frame (header_len + Udp_wire.sizeof_udp) in
      let udp_buf = Cstruct.shift frame header_len in
      Udp_wire.set_udp_source_port udp_buf source_port;
      Udp_wire.set_udp_dest_port udp_buf dest_port;
      Udp_wire.set_udp_length udp_buf (Udp_wire.sizeof_udp + Cstruct.lenv bufs);
      Udp_wire.set_udp_checksum udp_buf 0;
      let csum = Ip.checksum frame (udp_buf :: bufs) in
      Udp_wire.set_udp_checksum udp_buf csum;
      (* Ip.writev *)
      let bufs = frame :: bufs in
      let tlen = Cstruct.lenv bufs - Ethif_wire.sizeof_ethernet in
      let dmac = String.make 6 '\000' in
      (* Ip.adjust_output_header *)
      Ethif_wire.set_ethernet_dst dmac 0 frame;
      let buf =
        Cstruct.sub frame Ethif_wire.sizeof_ethernet Ipv4_wire.sizeof_ipv4
      in
      (* Set the mutable values in the ipv4 header *)
      Ipv4_wire.set_ipv4_len buf tlen;
      Ipv4_wire.set_ipv4_id buf (Random.int 65535); (* TODO *)
      Ipv4_wire.set_ipv4_csum buf 0;
      let checksum = Tcpip_checksum.ones_complement buf in
      Ipv4_wire.set_ipv4_csum buf checksum;
      Recorder.record recorder bufs
    | None ->
      () (* nowhere to log packet *)

  let create ~local_address ~host_names =
    let local_ip = local_address.Dns_forward.Config.Address.ip in
    Log.info (fun f ->
        f "DNS names %s will map to local IP %s"
          (String.concat ", " @@ List.map Dns.Name.to_string host_names)
          (Ipaddr.to_string local_ip));
    fun clock -> function
    | `Upstream config ->
      let open Dns_forward.Config.Address in
      let nr_servers =
        let open Dns_forward.Config in
        Server.Set.cardinal config.servers in
      Log.info (fun f -> f "%d upstream DNS servers are configured" nr_servers);

      let message_cb ?(src = local_address) ?(dst = local_address) ~buf () =
        match src, dst with
        | { ip = Ipaddr.V4 source_ip; port = source_port },
          { ip = Ipaddr.V4 dest_ip; port = dest_port } ->
          record_udp ~source_ip ~source_port ~dest_ip ~dest_port [ buf ];
          Lwt.return_unit
        | _ ->
          (* We don't know how to marshal IPv6 yet *)
          Lwt.return_unit in
      Dns_udp_resolver.create ~message_cb config clock
      >>= fun dns_udp_resolver ->
      Dns_tcp_resolver.create ~message_cb config clock
      >>= fun dns_tcp_resolver ->
      Lwt.return { local_ip; host_names;
                   resolver = Upstream { dns_tcp_resolver; dns_udp_resolver } }
    | `Host ->
      Log.info (fun f -> f "Will use the host's DNS resolver");
      Lwt.return { local_ip; host_names; resolver = Host }

  let answer t is_tcp buf =
    let open Dns.Packet in
    let len = Cstruct.len buf in
    match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
    | None ->
      Lwt.return (Error (`Msg "failed to parse DNS packet"))
    | Some ({ questions = [ question ]; _ } as request) ->
      let reply answers =
        let id = request.id in
        let detail =
          { request.detail with Dns.Packet.qr = Dns.Packet.Response; ra = true }
        in
        let questions = request.questions in
        let authorities = [] and additionals = [] in
        { Dns.Packet.id; detail; questions; answers; authorities; additionals }
      in
      begin
        match try_etc_hosts question with
        | Some answers ->
          Lwt.return (Ok (marshal @@ reply answers))
        | None ->
          match try_builtins t.local_ip t.host_names question with
          | Some answers ->
            Lwt.return (Ok (marshal @@ reply answers))
          | None ->
            match is_tcp, t.resolver with
            | true, Upstream { dns_tcp_resolver; _ } ->
              Dns_tcp_resolver.answer buf dns_tcp_resolver
            | false, Upstream { dns_udp_resolver; _ } ->
              Dns_udp_resolver.answer buf dns_udp_resolver
            | _, Host ->
              D.resolve question
              >>= function
              | [] ->
                let nxdomain =
                  let id = request.id in
                  let detail =
                    { request.detail with Dns.Packet.qr = Dns.Packet.Response;
                                          ra = true; rcode = Dns.Packet.NXDomain
                    } in
                  let questions = request.questions in
                  let authorities = [] and additionals = [] and answers = []
                  in
                  { Dns.Packet.id; detail; questions; answers; authorities;
                    additionals }
                in
                Lwt.return (Ok (marshal nxdomain))
              | answers ->
                Lwt.return (Ok (marshal @@ reply answers))
      end
    | _ ->
      Lwt.return (Error (`Msg "DNS packet had multiple questions"))

  let describe buf =
    let len = Cstruct.len buf in
    match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
    | None -> Printf.sprintf "Unparsable DNS packet length %d" len
    | Some request -> Dns.Packet.to_string request

  let handle_udp ~t ~udp ~src ~dst:_ ~src_port buf =
    answer t false buf
    >>= function
    | Error (`Msg m) ->
      Log.warn (fun f -> f "%s lookup failed: %s" (describe buf) m);
      Lwt.return (Ok ())
    | Ok buffer ->
      Udp.write ~src_port:53 ~dst:src ~dst_port:src_port udp buffer

  let handle_tcp ~t =
    (* FIXME: need to record the upstream request *)
    let listeners _ =
      Log.debug (fun f -> f "DNS TCP handshake complete");
      let f flow =
        let packets = Dns_tcp_framing.connect flow in
        let rec loop () =
          Dns_tcp_framing.read packets >>= function
          | Error _    -> Lwt.return_unit
          | Ok request ->
            (* Perform queries in background threads *)
            let queries () =
              answer t true request >>= function
              | Error (`Msg m) ->
                Log.warn (fun f -> f "%s lookup failed: %s" (describe request) m);
                Lwt.return_unit
              | Ok buffer ->
                Dns_tcp_framing.write packets buffer >>= function
                | Error (`Msg m) ->
                  Log.warn (fun f ->
                      f "%s failed to write response: %s" (describe buffer) m);
                  Lwt.return_unit
                | Ok () ->
                  Lwt.return_unit
            in
            Lwt.async queries;
            loop ()
        in
        loop ()
      in
      Some f
    in
    Lwt.return listeners

end
