let src =
  let src = Logs.Src.create "port forward" ~doc:"forward local ports to the VM" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix
open Vmnet

let is_windows = Sys.os_type = "Win32"

module Make(Socket: Sig.SOCKETS) = struct

  module Channel = Mirage_channel_lwt.Make(Socket.Stream.Unix)

  type t = {
    fd: Socket.Stream.Unix.flow;
    c: Channel.t;
  }

  let register_connection = Socket.register_connection
  let deregister_connection = Socket.deregister_connection
  let set_max_connections = Socket.set_max_connections
  let get_num_connections = Socket.get_num_connections
  let connections = Socket.connections
  exception Too_many_connections = Socket.Too_many_connections

  let of_fd fd =
    let buf = Cstruct.create Init.sizeof in
    let (_: Cstruct.t) = Init.marshal Init.default buf in
    let c = Channel.create fd in
    let open Lwt_result.Infix in
    Channel.write_buffer c buf;
    Channel.flush c >>= fun () ->
    Channel.read_exactly ~len:Init.sizeof c >>= function
    | `Eof       -> Lwt_result.fail `Eof
    | `Data bufs ->
      let buf = Cstruct.concat bufs in
      let open Lwt_result.Infix in
      Lwt.return (Init.unmarshal buf)
      >>= fun (init, _) ->
        Log.info (fun f ->
          f "Client.negotiate: received %s" (Init.to_string init));
        Lwt_result.return { fd; c }
      )

  let bind_ipv4 t (ipv4, port, stream) =
    let buf = Cstruct.create Command.sizeof in
    let (_: Cstruct.t) =
      Command.marshal (Command.Bind_ipv4(ipv4, port, stream)) buf
    in
    Channel.write_buffer t.c buf;
    Channel.flush t.c >>= fun () ->
    let rawfd = Socket.Stream.Unix.unsafe_get_raw_fd t.fd in
    let result = String.make 8 '\000' in
    let n, _, fd = Fd_send_recv.recv_fd rawfd result 0 8 [] in

    (if n <> 8 then errorf "Message only contained %d bytes" n else
       let buf = Cstruct.create 8 in
       Cstruct.blit_from_string result 0 buf 0 8;
       Log.debug (fun f ->
           let b = Buffer.create 16 in
           Cstruct.hexdump_to_buffer b buf;
           f "received result bytes: %s which is %s" (String.escaped result)
             (Buffer.contents b));
       match Cstruct.LE.get_uint64 buf 0 with
       | 0L  -> Lwt.return (`Ok fd)
       | 48L -> errorf "EADDRINUSE"
       | 49L -> errorf "EADDRNOTAVAIL"
       | n   -> errorf "Failed to bind: unrecognised errno: %Ld" n
    ) >>= function
    | `Error x ->
      Unix.close fd;
      Lwt_result.fail x
    | `Ok x ->
      Lwt_result.return x

  (* This implementation is OSX-only *)
  let request_privileged_port local_ip local_port sock_stream =
    let open Lwt_result.Infix in
    Socket.Stream.Unix.connect "/var/tmp/com.docker.vmnetd.socket"
    >>= fun flow ->
    Lwt.finalize (fun () ->
        of_fd flow >>= fun c ->
        bind_ipv4 c (local_ip, local_port, sock_stream)
      ) (fun () -> Socket.Stream.Unix.close flow)

  module Datagram = struct
    type address = Socket.Datagram.address

    module Udp = struct
      include Socket.Datagram.Udp

      let bind ?description (local_ip, local_port) =
        match local_ip with
        | Ipaddr.V4 ipv4 ->
          if local_port < 1024 && not is_windows then
            request_privileged_port ipv4 local_port false >>= function
            | Error (`Msg x) -> Lwt.fail_with x
            | Ok fd          -> Lwt.return (Socket.Datagram.Udp.of_bound_fd fd)
          else
            bind ?description (local_ip, local_port)
        | _ -> bind ?description (local_ip, local_port)
    end
  end

  module Stream = struct
    module Tcp = struct
      include Socket.Stream.Tcp

      let bind ?description (local_ip, local_port) =
        match local_ip with
        | Ipaddr.V4 ipv4 ->
          if local_port < 1024 && not is_windows then
            request_privileged_port ipv4 local_port true >>= function
            | Error (`Msg x) -> Lwt.fail_with x
            | Ok fd          -> Lwt.return (Socket.Stream.Tcp.of_bound_fd fd)
          else
            bind ?description (local_ip, local_port)
        | _ -> bind ?description (local_ip, local_port)
    end

    module Unix = Socket.Stream.Unix
  end
end
