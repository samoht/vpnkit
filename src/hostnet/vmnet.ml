open Lwt.Infix

let src =
  let src = Logs.Src.create "vmnet" ~doc:"vmnet" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let ethernet_header_length = 14 (* no VLAN *)

module Init = struct

  type t = {
    magic: string;
    version: int32;
    commit: string;
  }

  let to_string t =
    Fmt.strf "{ magic = %s; version = %ld; commit = %s }"
      t.magic t.version t.commit

  let sizeof = 5 + 4 + 40

  let default = {
    magic = "VMN3T";
    version = 1l;
    commit = "0123456789012345678901234567890123456789";
  }

  let marshal t rest =
    Cstruct.blit_from_string t.magic 0 rest 0 5;
    Cstruct.LE.set_uint32 rest 5 t.version;
    Cstruct.blit_from_string t.commit 0 rest 9 40;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let magic = Cstruct.(to_string @@ sub rest 0 5) in
    let version = Cstruct.LE.get_uint32 rest 5 in
    let commit = Cstruct.(to_string @@ sub rest 9 40) in
    let rest = Cstruct.shift rest sizeof in
    { magic; version; commit }, rest
end

module Command = struct

  type t =
    | Ethernet of Uuidm.t (* 36 bytes *)
    | Bind_ipv4 of Ipaddr.V4.t * int * bool

  let to_string = function
  | Ethernet x -> Fmt.strf "Ethernet %a" Uuidm.pp x
  | Bind_ipv4 (ip, port, tcp) ->
    Fmt.strf "Bind_ipv4 %a %d %b" Ipaddr.V4.pp_hum ip port tcp

  let sizeof = 1 + 36

  let marshal t rest = match t with
  | Ethernet uuid ->
    Cstruct.set_uint8 rest 0 1;
    let rest = Cstruct.shift rest 1 in
    let uuid_str = Uuidm.to_string uuid in
    Cstruct.blit_from_string uuid_str 0 rest 0 (String.length uuid_str);
    Cstruct.shift rest (String.length uuid_str)
  | Bind_ipv4 (ip, port, stream) ->
    Cstruct.set_uint8 rest 0 6;
    let rest = Cstruct.shift rest 1 in
    Cstruct.LE.set_uint32 rest 0 (Ipaddr.V4.to_int32 ip);
    let rest = Cstruct.shift rest 4 in
    Cstruct.LE.set_uint16 rest 0 port;
    let rest = Cstruct.shift rest 2 in
    Cstruct.set_uint8 rest 0 (if stream then 0 else 1);
    Cstruct.shift rest 1

  let unmarshal rest =
    match Cstruct.get_uint8 rest 0 with
    | 1 ->
      let uuid_str = Cstruct.(to_string (sub rest 1 36)) in
      let rest = Cstruct.shift rest 37 in
      if (Bytes.compare (Bytes.make 36 '\000') uuid_str) = 0 then
        begin
          let random_uuid = (Uuidm.v `V4) in
          Log.info (fun f ->
              f "Generated UUID on behalf of client: %a" Uuidm.pp random_uuid);
          (* generate random uuid on behalf of client if client sent
             array of \0 *)
          Ok (Ethernet random_uuid, rest)
        end else  begin
        let result = match (Uuidm.of_string uuid_str) with
        (* parse uuid from client *)
        | Some uuid -> Ok (Ethernet uuid, rest)
        | None      -> Error (`Msg (Printf.sprintf "Invalid UUID: %s" uuid_str))
        in
        result
      end
    | n -> Error (`Msg (Printf.sprintf "Unknown command: %d" n))

end

module Vif = struct

  type t = {
    mtu: int;
    max_packet_size: int;
    client_macaddr: Macaddr.t;
  }

  let to_string t =
    Fmt.strf "{ mtu = %d; max_packet_size = %d; client_macaddr = %s }"
      t.mtu t.max_packet_size (Macaddr.to_string t.client_macaddr)

  let create client_macaddr mtu () =
    let max_packet_size = mtu + 50 in
    { mtu; max_packet_size; client_macaddr }

  let sizeof = 2 + 2 + 6

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t.mtu;
    Cstruct.LE.set_uint16 rest 2 t.max_packet_size;
    Cstruct.blit_from_bytes (Macaddr.to_bytes t.client_macaddr) 0 rest 4 6;
    Cstruct.shift rest sizeof

  let unmarshal rest =
    let mtu = Cstruct.LE.get_uint16 rest 0 in
    let max_packet_size = Cstruct.LE.get_uint16 rest 2 in
    let mac = Cstruct.(to_string @@ sub rest 4 6) in
    try
      let client_macaddr = Macaddr.of_bytes_exn mac in
      Ok ({ mtu; max_packet_size; client_macaddr }, Cstruct.shift rest sizeof)
    with _ ->
      Error (`Msg (Printf.sprintf "Failed to parse MAC: [%s]" mac))

end

module Packet = struct
  let sizeof = 2

  let marshal t rest =
    Cstruct.LE.set_uint16 rest 0 t

  let unmarshal rest =
    let t = Cstruct.LE.get_uint16 rest 0 in
    Ok (t, Cstruct.shift rest sizeof)
end

module Make(C: Sig.CONN) = struct

  module Channel = Mirage_channel_lwt.Make(C)

  type page_aligned_buffer = Io_page.t
  type macaddr = Macaddr.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type error = [Mirage_device.error | `Channel of Channel.write_error]

  let pp_error ppf = function
  | #Mirage_device.error as e -> Mirage_device.pp_error ppf e
  | `Channel e                -> Channel.pp_write_error ppf e

  let failf fmt = Fmt.kstrf (fun e -> Lwt_result.fail (`Msg e)) fmt

  type t = {
    mutable fd: Channel.t option;
    stats: Mirage_net.stats;
    client_uuid: Uuidm.t;
    client_macaddr: Macaddr.t;
    server_macaddr: Macaddr.t;
    mtu: int;
    mutable write_header: Cstruct.t;
    write_m: Lwt_mutex.t;
    mutable pcap: Unix.file_descr option;
    mutable pcap_size_limit: int64 option;
    pcap_m: Lwt_mutex.t;
    mutable listeners: (Cstruct.t -> unit Lwt.t) list;
    mutable listening: bool;
    after_disconnect: unit Lwt.t;
    after_disconnect_u: unit Lwt.u;
  }

  let get_client_uuid t =
    t.client_uuid

  let get_client_macaddr t =
    t.client_macaddr

  let err_eof = Lwt_result.fail (`Msg "error: got EOF")
  let err_read e = failf "error while reading: %a" Channel.pp_error e
  let err_flush e = failf "error while flushing: %a" Channel.pp_write_error e

  let with_read x f =
    x >>= function
    | Error e      -> err_read e
    | Ok `Eof      -> err_eof
    | Ok (`Data x) -> f x

  let with_flush x f =
    x >>= function
    | Error e -> err_flush e
    | Ok ()   -> f ()

  let with_msg x f =
    match x with
    | Ok x -> f x
    | Error _ as e -> Lwt.return e

  let server_negotiate ~fd ~client_macaddr_of_uuid ~mtu =
    with_read (Channel.read_exactly ~len:Init.sizeof fd) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    let init, _ = Init.unmarshal buf in
    Log.info (fun f -> f "PPP.negotiate: received %s" (Init.to_string init));
    let (_: Cstruct.t) = Init.marshal Init.default buf in
    Channel.write_buffer fd buf;
    with_flush (Channel.flush fd) @@ fun () ->
    with_read (Channel.read_exactly ~len:Command.sizeof fd) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    with_msg (Command.unmarshal buf) @@ fun (command, _) ->
    Log.info (fun f ->
        f "PPP.negotiate: received %s" (Command.to_string command));
    match command with
    | Command.Bind_ipv4 _ -> failf "PPP.negotiate: unsupported command Bind_ipv4"
    | Command.Ethernet uuid ->
      client_macaddr_of_uuid uuid >>= fun client_macaddr ->
      let vif = Vif.create client_macaddr mtu () in
      let buf = Cstruct.create Vif.sizeof in
      let (_: Cstruct.t) = Vif.marshal vif buf in
      Log.info (fun f -> f "PPP.negotiate: sending %s" (Vif.to_string vif));
      Channel.write_buffer fd buf;
      with_flush (Channel.flush fd) @@ fun () ->
      Lwt_result.return (uuid, client_macaddr)

  let client_negotiate ~uuid ~fd =
    let buf = Cstruct.create Init.sizeof in
    let (_: Cstruct.t) = Init.marshal Init.default buf in
    Channel.write_buffer fd buf;
    with_flush (Channel.flush fd) @@ fun () ->
    with_read (Channel.read_exactly ~len:Init.sizeof fd) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    let init, _ = Init.unmarshal buf in
    Log.info (fun f -> f "Client.negotiate: received %s" (Init.to_string init));
    let buf = Cstruct.create Command.sizeof in
    let (_: Cstruct.t) = Command.marshal (Command.Ethernet uuid) buf in
    Channel.write_buffer fd buf;
    with_flush (Channel.flush fd) @@ fun () ->
    with_read (Channel.read_exactly ~len:Vif.sizeof fd) @@ fun bufs ->
    let buf = Cstruct.concat bufs in
    let open Lwt_result.Infix in
    Lwt.return (Vif.unmarshal buf) >>= fun (vif, _) ->
    Log.debug (fun f -> f "Client.negotiate: vif %s" (Vif.to_string vif));
    Lwt_result.return (vif)

  (* Use blocking I/O here so we can avoid Using Lwt_unix or Uwt. Ideally we
     would use a FLOW handle referencing a file/stream. *)
  let really_write fd str =
    let rec loop ofs =
      if ofs = (String.length str)
      then ()
      else
        let n = Unix.write fd str ofs (String.length str - ofs) in
        loop (ofs + n)
    in
    loop 0

  let start_capture t ?size_limit filename =
    Lwt_mutex.with_lock t.pcap_m (fun () ->
        (match t.pcap with Some fd -> Unix.close fd | None -> ());
        let fd =
          Unix.openfile filename [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ]
            0o0644
        in
        let buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
        let open Pcap.LE in
        set_pcap_header_magic_number buf Pcap.magic_number;
        set_pcap_header_version_major buf Pcap.major_version;
        set_pcap_header_version_minor buf Pcap.minor_version;
        set_pcap_header_thiszone buf 0l;
        set_pcap_header_sigfigs buf 4l;
        set_pcap_header_snaplen buf 1500l;
        set_pcap_header_network buf
          (Pcap.Network.to_int32 Pcap.Network.Ethernet);
        really_write fd (Cstruct.to_string buf);
        t.pcap <- Some fd;
        t.pcap_size_limit <- size_limit;
        Lwt.return ()
      )

  let stop_capture_already_locked t = match t.pcap with
  | None    -> ()
  | Some fd ->
    Unix.close fd;
    t.pcap <- None;
    t.pcap_size_limit <- None

  let stop_capture t =
    Lwt_mutex.with_lock t.pcap_m  (fun () ->
        stop_capture_already_locked t;
        Lwt.return_unit
      )

  let make ~client_macaddr ~server_macaddr ~mtu ~client_uuid fd =
    let fd = Some fd in
    let stats = Mirage_net.Stats.create () in
    let write_header = Cstruct.create (1024 * Packet.sizeof) in
    let write_m = Lwt_mutex.create () in
    let pcap = None in
    let pcap_size_limit = None in
    let pcap_m = Lwt_mutex.create () in
    let listeners = [] in
    let listening = false in
    let after_disconnect, after_disconnect_u = Lwt.task () in
    { fd; stats; client_macaddr; client_uuid; server_macaddr; mtu; write_header;
      write_m; pcap; pcap_size_limit; pcap_m; listeners; listening;
      after_disconnect; after_disconnect_u }

  type fd = C.flow

  let of_fd ~client_macaddr_of_uuid ~server_macaddr ~mtu flow =
    let open Lwt_result.Infix in
    let channel = Channel.create flow in
    server_negotiate ~fd:channel ~client_macaddr_of_uuid ~mtu
    >>= fun (client_uuid, client_macaddr) ->
    let t = make ~client_macaddr ~server_macaddr ~mtu ~client_uuid channel in
    Lwt_result.return t

  let client_of_fd ~uuid ~server_macaddr flow =
    let open Lwt_result.Infix in
    let channel = Channel.create flow in
    client_negotiate ~uuid ~fd:channel
    >>= fun vif ->
    let t =
      make ~client_macaddr:vif.Vif.client_macaddr
        ~server_macaddr:server_macaddr ~mtu:vif.Vif.mtu ~client_uuid:uuid
        channel in
    Lwt_result.return t

  let disconnect t = match t.fd with
  | None    -> Lwt.return ()
  | Some fd ->
    t.fd <- None;
    Log.debug (fun f -> f "Vmnet.disconnect flushing channel");
    (Channel.flush fd >|= function
      | Ok ()   -> ()
      | Error e ->
        Log.err (fun l ->
            l "error while disconnecting the vmtnet connection: %a"
              Channel.pp_write_error e);
    ) >|= fun () ->
    Lwt.wakeup_later t.after_disconnect_u ()

  let after_disconnect t = t.after_disconnect

  let capture t bufs =
    match t.pcap with
    | None -> Lwt.return ()
    | Some pcap ->
      Lwt_mutex.with_lock t.pcap_m (fun () ->
          let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
          let time = Unix.gettimeofday () in
          let secs = Int32.of_float time in
          let usecs = Int32.of_float (1e6 *. (time -. (floor time))) in
          let buf = Cstruct.create Pcap.sizeof_pcap_packet in
          let open Pcap.LE in
          set_pcap_packet_ts_sec buf secs;
          set_pcap_packet_ts_usec buf usecs;
          set_pcap_packet_incl_len buf @@ Int32.of_int len;
          set_pcap_packet_orig_len buf @@ Int32.of_int len;
          really_write pcap (Cstruct.to_string buf);
          List.iter (fun buf -> really_write pcap (Cstruct.to_string buf)) bufs;
          match t.pcap_size_limit with
          | None -> Lwt.return () (* no limit *)
          | Some limit ->
            let limit = Int64.(sub limit (of_int len)) in
            t.pcap_size_limit <- Some limit;
            if limit < 0L then stop_capture_already_locked t;
            Lwt.return_unit
        )

  let writev t bufs =
    Lwt_mutex.with_lock t.write_m (fun () ->
        capture t bufs >>= fun () ->
        let len = List.(fold_left (+) 0 (map Cstruct.len bufs)) in
        if len > (t.mtu + ethernet_header_length) then begin
          Log.err (fun f ->
              f "Dropping over-large ethernet frame, length = %d, mtu = \
                 %d" len t.mtu
            );
          Lwt_result.return ()
        end else begin
          let buf = Cstruct.create Packet.sizeof in
          Packet.marshal len buf;
          match t.fd with
          | None    -> Lwt_result.fail `Disconnected
          | Some fd ->
            Channel.write_buffer fd buf;
            Log.debug (fun f ->
                let b = Buffer.create 128 in
                List.iter (Cstruct.hexdump_to_buffer b) bufs;
                f "sending\n%s" (Buffer.contents b)
              );
            List.iter (Channel.write_buffer fd) bufs;
            Channel.flush fd >|= function
            | Ok ()   -> Ok ()
            | Error e -> Error (`Channel e)
        end
      )

  let err_eof =
    Log.debug (fun f -> f "PPP.listen: closing connection");
    Lwt.return false

  let err_unexpected t pp e =
    Log.err (fun f ->
        f "PPP.listen: caught unexpected %a: disconnecting" pp e);
    disconnect t >>= fun () ->
    Lwt.return false

  let with_fd t f = match t.fd with
  | None    -> Lwt.return false
  | Some fd -> f fd

  let with_read t x f =
    x >>= function
    | Error e      -> err_unexpected t Channel.pp_error e
    | Ok `Eof      -> err_eof
    | Ok (`Data x) -> f x

  let with_msg t x f =
    match x with
    | Error (`Msg e) -> err_unexpected t Fmt.string e
    | Ok x           -> f x

  let listen t callback =
    if t.listening then begin
      Log.debug (fun f -> f "PPP.listen: called a second time: doing nothing");
      Lwt.return (Ok ());
    end else begin
      t.listening <- true;
      let last_error_log = ref 0. in
      let rec loop () =
        (with_fd t @@ fun fd ->
         with_read t (Channel.read_exactly ~len:Packet.sizeof fd) @@ fun bufs ->
         let read_header = Cstruct.concat bufs in
         with_msg t (Packet.unmarshal read_header) @@ fun (len, _) ->
         with_read t (Channel.read_exactly ~len fd) @@ fun bufs ->
         capture t bufs >>= fun () ->
         Log.debug (fun f ->
             let b = Buffer.create 128 in
             List.iter (Cstruct.hexdump_to_buffer b) bufs;
             f "received\n%s" (Buffer.contents b)
           );
         let buf = Cstruct.concat bufs in
         let callback buf =
           Lwt.catch (fun () -> callback buf)
             (function
             | Host_uwt.Sockets.Too_many_connections
             | Host_lwt_unix.Sockets.Too_many_connections ->
               (* No need to log this again *)
               Lwt.return_unit
             | e ->
               let now = Unix.gettimeofday () in
               if (now -. !last_error_log) > 30. then begin
                 Log.err (fun f ->
                     f "PPP.listen callback caught %a" Fmt.exn e);
                 last_error_log := now;
               end;
               Lwt.return_unit
             )
         in
         Lwt.async (fun () -> callback buf);
         List.iter (fun callback ->
             Lwt.async (fun () -> callback buf)
           ) t.listeners;
         Lwt.return true
        ) >>= function
        | true  -> loop ()
        | false -> Lwt.return ()
      in
      Lwt.async @@ loop;
      Lwt.return (Ok ());
    end


  let write t buf =
    Lwt_mutex.with_lock t.write_m (fun () ->
        capture t [ buf ] >>= fun () ->
        let len = Cstruct.len buf in
        if len > (t.mtu + ethernet_header_length) then begin
          Log.err (fun f ->
              f "Dropping over-large ethernet frame, length = %d, mtu = \
                 %d" len t.mtu
            );
          Lwt.return (Ok ())
        end else begin
          if Cstruct.len t.write_header < Packet.sizeof then begin
            t.write_header <- Cstruct.create (1024 * Packet.sizeof)
          end;
          Packet.marshal len t.write_header;
          match t.fd with
          | None    -> Lwt.return (Error `Disconnected)
          | Some fd ->
            Channel.write_buffer fd
              (Cstruct.sub t.write_header 0 Packet.sizeof);
            t.write_header <- Cstruct.shift t.write_header Packet.sizeof;
            Log.debug (fun f ->
                let b = Buffer.create 128 in
                Cstruct.hexdump_to_buffer b buf;
                f "sending\n%s" (Buffer.contents b)
              );
            Channel.write_buffer fd buf;
            Channel.flush fd >|= function
            | Ok ()   -> Ok ()
            | Error e -> Error (`Channel e)
        end)

  let add_listener t callback = t.listeners <- callback :: t.listeners
  let mac t = t.server_macaddr
  let get_stats_counters t = t.stats
  let reset_stats_counters t = Mirage_net.Stats.reset t.stats

end
