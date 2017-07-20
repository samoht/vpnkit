open Lwt_result.Infix
open Astring

let src =
  let src = Logs.Src.create "http" ~doc:"Transparently proxy HTTP" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Exclude = struct

  module One = struct
    module Element = struct
      type t =
        | Any
        | String of string
      (* One element of a DNS name *)

      let of_string = function
        | "*" -> Any
        | x -> String x
      let to_string = function
        | Any -> "*"
        | String x -> x
      let matches x = function
        | Any -> true
        | String y -> x = y
    end

    type t =
      | Subdomain of Element.t list
      | CIDR of Ipaddr.V4.Prefix.t

    let of_string s =
      match Ipaddr.V4.Prefix.of_string s with
      | Some prefix -> CIDR prefix
      | None ->
        let bits = Astring.String.cuts ~sep:"." s in
        Subdomain (List.map Element.of_string bits)

    let to_string = function
      | Subdomain x ->
        "Subdomain " ^ (String.concat ~sep:"." @@ List.map Element.to_string x)
      | CIDR prefix -> "CIDR " ^ (Ipaddr.V4.Prefix.to_string prefix)

    let matches dst req = function
      | CIDR prefix -> Ipaddr.V4.Prefix.mem dst prefix
      | Subdomain domains ->
        match req with
        | None -> false
        | Some req ->
          let h = req.Cohttp.Request.headers in
          match Cohttp.Header.get h "host" with
          | None -> false
          | Some host ->
            let bits = Astring.String.cuts ~sep:"." host in
            (* does 'bits' match 'domains' *)
            let rec loop bits domains = match bits, domains with
              | _, [] -> true
              | [], _ :: _ -> false
              | b :: bs, d :: ds -> Element.matches b d && loop bs ds
            in
            loop (List.rev bits) (List.rev domains)
  end

  type t = One.t list

  let none = []

  let of_string s =
    let open Astring in
    (* Accept either space or comma-separated ignoring whitespace *)
    let parts =
      String.fields
        ~empty:false ~is_sep:(fun c -> c = ',' || Char.Ascii.is_white c) s
    in
    List.map One.of_string parts

  let to_string t = String.concat ~sep:" " @@ (List.map One.to_string t)

  let matches dst req t = List.fold_left (||) false (List.map (One.matches dst req) t)

end

module Make
    (Ip: Mirage_protocols_lwt.IPV4)
    (Udp: Mirage_protocols_lwt.UDPV4)
    (Tcp:Mirage_flow_lwt.SHUTDOWNABLE)
    (Socket: Sig.SOCKETS)
    (Dns_resolver: Sig.DNS) =
struct

  type address = Ipaddr.t * int

  let pp_address ppf (ip, port) = Fmt.pf ppf "%s:%d" (Ipaddr.to_string ip) port
  let string_of_address = Fmt.to_to_string pp_address

  type t = {
    http: address option;
    https: address option;
    exclude: Exclude.t;
  }

  type error = [
    | `Invalid_port of string
    | `No_port of string
    | `Lookup_failed of string
  ]

  let errorf fmt = Fmt.kstrf (fun s -> (Error (`Msg s))) fmt

  let err_invalid_port p = errorf "Failed to parse port: %s" p
  let err_lookup_failed s = errorf "Failed to lookup host: %s" s
  let err_no_port p = errorf "Failed to find a :port in %s" p
  let err_invalid_address s = errorf "Failed to parse proxy address: %s" s

  let parse_host_port x =
    (* host:port or [host]:port *)
    let find_host name_or_ip =
      match Ipaddr.of_string name_or_ip with
      | None ->
        let open Dns.Packet in
        let question =
          make_question ~q_class:Q_IN Q_A (Dns.Name.of_string name_or_ip)
        in
        Lwt.Infix.(
          Dns_resolver.resolve question >|= function
          | { cls = RR_IN; rdata = A ipv4; _ } :: _ -> Ok (Ipaddr.V4 ipv4)
          | _ -> err_lookup_failed name_or_ip
        )
      | Some x -> Lwt.return (Ok x)
    in
    let parse_port port =
      match int_of_string port with
      | x           -> Lwt.return (Ok x)
      | exception _ -> Lwt.return (err_invalid_port port)
    in
    (* Is it a URL? *)
    let uri = Uri.of_string x in
    match Uri.host uri, Uri.port uri with
    | Some host, Some port ->
      find_host host >|= fun ip ->
      Some (ip, port)
    | _, _ ->
      match String.cuts ~sep:":" x with
      | [] -> Lwt.return (err_no_port x)
      | [host; port] ->
        find_host host >>= fun ip ->
        parse_port port >|= fun port ->
        Some (ip, port)
      | _ -> Lwt.return (err_invalid_address x)

  let to_json t =
    let open Ezjsonm in
    let http = match t.http with
      | None   -> []
      | Some x -> [ "http",  string @@ string_of_address x ]
    in
    let https = match t.https with
      | None   -> []
      | Some x -> [ "https", string @@ string_of_address x ]
    in
    let exclude = [ "exclude", string @@ Exclude.to_string t.exclude ] in
    dict (http @ https @ exclude)

  let of_json j =
    let open Ezjsonm in
    let http =
      try Some (get_string @@ find j [ "http" ])
      with Not_found -> None
    in
    let https =
      try Some (get_string @@ find j [ "https" ])
      with Not_found -> None
    in
    let exclude =
      try Exclude.of_string @@ get_string @@ find j [ "exclude" ]
      with Not_found -> Exclude.none
    in
    let open Lwt_result.Infix in
    (match http with
     | None   -> Lwt.return (Ok None)
     | Some x -> parse_host_port x)
    >>= fun http ->
    (match https with
     | None   -> Lwt.return (Ok None)
     | Some x -> parse_host_port x)
    >|= fun https ->
    { http; https; exclude }

  let to_string t = Ezjsonm.to_string ~minify:false @@ to_json t

  let create ?http ?https ?exclude:_ () =
    let open Lwt_result.Infix in
    (match http with
     | None      -> Lwt.return (Ok None)
     | Some http -> parse_host_port http )
    >>= fun http ->
    (match https with
     | None       -> Lwt.return (Ok None)
     | Some https -> parse_host_port https )
    >|= fun https ->
    (* FIXME: parse excludes *)
    let exclude = [] in
    let t = { http; https; exclude } in
    Log.info (fun f -> f "HTTP proxy settings changed to: %s" (to_string t));
    t

  module Incoming = struct
    module C = Mirage_channel_lwt.Make(Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end
  module Outgoing = struct
    module C = Mirage_channel_lwt.Make(Socket.Stream.Tcp)
    module IO = Cohttp_mirage_io.Make(C)
    module Request = Cohttp.Request.Make(IO)
    module Response = Cohttp.Response.Make(IO)
  end

  let proxy_one ~dst ~t incoming h =
    let open Lwt.Infix in
    Incoming.Request.read incoming >>= function
    | `Eof       -> Lwt.return_unit
    | `Invalid x ->
      Log.warn (fun f -> f "Failed to parse HTTP request on port %s:80: %s"
                   (Ipaddr.V4.to_string dst) x);
      Lwt.return_unit
    | `Ok req ->

      (* The scheme from cohttp is missing. If we send to an HTTP proxy
         then we need it. *)
      let uri = Uri.with_scheme (Cohttp.Request.uri req) (Some "http") in
      let address =
        if Exclude.matches dst (Some req) t.exclude
        then Ipaddr.V4 dst, 80 (* direct connection *)
        else h in
      (* Log the request to the console *)
      let description outgoing =
        Printf.sprintf "%s:80 %s %s:%d Host:%s"
          (Ipaddr.V4.to_string dst)
          (if outgoing then "-->" else "<--")
          (Ipaddr.to_string @@ fst address)
          (snd address)
          (match Uri.host uri with Some x -> x | None -> "(unknown host)") in
      Log.info (fun f -> f "%s: %s %s"
                   (description true)
                   (Cohttp.(Code.string_of_method (Cohttp.Request.meth req)))
                   (Uri.path uri)
               );
      Socket.Stream.Tcp.connect address >>= function
      | Error _ ->
        Log.err (fun f -> f "Failed to connect to %a" pp_address address);
        Lwt.return_unit
      | Ok remote ->
        (* Make the resource a full URI *)
        let req = { req with Cohttp.Request.resource = Uri.to_string uri } in

        Lwt.finalize (fun () ->
            let outgoing = Outgoing.C.create remote in
            let reader = Incoming.Request.make_body_reader req incoming in
            Outgoing.Request.write ~flush:true
              (fun writer ->
                 let rec proxy_body () =
                   let open Cohttp.Transfer in
                   Incoming.Request.read_body_chunk reader >>= function
                   | Done          -> Lwt.return_unit
                   | Final_chunk x -> Outgoing.Request.write_body writer x
                   | Chunk x       ->
                     Outgoing.Request.write_body writer x >>= proxy_body
                 in
                 match Incoming.Request.has_body req with
                 | `Yes     -> proxy_body ()
                 | `No      -> Lwt.return_unit
                 | `Unknown ->
                   Log.warn (fun f -> f "Request.has_body returned `Unknown: \
                                         not sure what to do");
                   Lwt.return_unit
              ) req outgoing
            >>= fun () ->
            Outgoing.Response.read outgoing >>= function
            | `Eof ->
              Log.warn (fun f -> f "EOF from %s" (string_of_address address));
              Lwt.return_unit
            | `Invalid x ->
              Log.warn (fun f -> f "Failed to parse HTTP response on port %s: %s"
                           (string_of_address address) x);
              Lwt.return_unit
            | `Ok res ->
              Log.info (fun f -> f "%s: %s %s"
                           (description false)
                           (Cohttp.Code.string_of_version res.Cohttp.Response.version)
                           (Cohttp.Code.string_of_status res.Cohttp.Response.status)
                       );
              Log.debug (fun f ->
                  f "%s" (Sexplib.Sexp.to_string_hum (Cohttp.Response.sexp_of_t res)));
              let reader = Outgoing.Response.make_body_reader res outgoing in
              Incoming.Response.write ~flush:true (fun writer ->
                  let rec proxy_body () =
                    let open Cohttp.Transfer in
                    Outgoing.Response.read_body_chunk reader >>= function
                    | Done          -> Lwt.return_unit
                    | Final_chunk x -> Incoming.Response.write_body writer x
                    | Chunk x       ->
                      Incoming.Response.write_body writer x >>= proxy_body
                  in
                  match Incoming.Response.has_body res with
                  | `Yes     -> proxy_body ()
                  | `No      -> Lwt.return_unit
                  | `Unknown ->
                    Log.warn (fun f -> f "Response.has_body returned `Unknown: \
                                          not sure what to do");
                    Lwt.return_unit
                ) res incoming
          ) (fun () -> Socket.Stream.Tcp.close remote)

  let http ~dst ~t h =
    let open Lwt.Infix in
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      let f flow =
        let open Lwt.Infix in
        let incoming = Incoming.C.create flow in
        Lwt.finalize (fun () ->
            let rec loop () = proxy_one ~dst ~t incoming h >>= loop in
            loop ()
          ) (fun () -> Tcp.close flow)
      in
      Some f
    in
    Lwt.return listeners

  let https ~dst ((ip, port) as address) =
    let open Lwt.Infix in
    let listeners _port =
      Log.debug (fun f -> f "HTTPS TCP handshake complete");
      let f flow =
        Lwt.finalize (fun () ->
            let host = Ipaddr.V4.to_string dst in
            let description outgoing =
              Printf.sprintf "%s:443 %s %s:%d"
                host (if outgoing then "-->" else "<--") (Ipaddr.to_string ip)
                port
            in
            Log.info (fun f -> f "%s: CONNECT" (description true));
            let connect =
              let c = Cohttp.Request.make ~meth:`CONNECT (Uri.make ()) in
              let resource = Fmt.strf "%s:%d" (Ipaddr.V4.to_string dst) 443 in
              { c with Cohttp.Request.resource }
            in
            Socket.Stream.Tcp.connect address >>= function
            | Error _ ->
              Log.err (fun f -> f "Failed to connect to %a" pp_address address);
              Lwt.return_unit
            | Ok remote ->
              let outgoing = Outgoing.C.create remote in
              Lwt.finalize (fun () ->
                  Outgoing.Request.write ~flush:true (fun _ -> Lwt.return_unit)
                    connect outgoing
                  >>= fun () ->
                  Outgoing.Response.read outgoing >>= function
                  | `Eof ->
                    Log.warn (fun f ->
                        f "EOF from %s" (string_of_address address));
                    Lwt.return_unit
                  | `Invalid x ->
                    Log.warn (fun f -> f "Failed to parse HTTP response on \
                                          port %s: %s"
                                 (string_of_address address) x);
                    Lwt.return_unit
                  | `Ok res ->
                    Log.info (fun f ->
                        let open Cohttp.Response in
                        f "%s: %s %s"
                          (description false)
                          (Cohttp.Code.string_of_version res.version)
                          (Cohttp.Code.string_of_status res.status)
                      );
                    Log.debug (fun f ->
                        f "%s"
                          (Sexplib.Sexp.to_string_hum
                             (Cohttp.Response.sexp_of_t res))
                      );
                    (* Since we've already layered a channel on top, we
                       can't use the Mirage_flow.proxy since it would
                       miss the contents already buffered. Therefore we
                       write out own channel-level proxy here: *)
                    let incoming = Incoming.C.create flow in
                    let error pp e =
                      Log.warn (fun f ->
                          f "Possibly unexpected exeption %a in proxy" pp e);
                      Lwt.return false
                    in
                    let a_t =
                      let rec loop () =
                        (Outgoing.C.read_some outgoing >>= function
                          | Ok `Eof        -> Lwt.return false
                          | Error e        -> error Outgoing.C.pp_error e
                          | Ok (`Data buf) ->
                            Incoming.C.write_buffer incoming buf;
                            Incoming.C.flush incoming >>= function
                            | Ok ()   -> Lwt.return true
                            | Error e -> error Incoming.C.pp_write_error e
                        ) >>= fun continue ->
                        if continue then loop () else
                          Tcp.shutdown_write flow
                      in
                      loop ()
                    in
                    let b_t =
                      let rec loop () =
                        (Incoming.C.read_some incoming >>= function
                          | Ok `Eof -> Lwt.return false
                          | Error e -> error Incoming.C.pp_error e
                          | Ok (`Data buf) ->
                            Outgoing.C.write_buffer outgoing buf;
                            Outgoing.C.flush outgoing >>= function
                            | Ok ()   -> Lwt.return true
                            | Error e -> error Outgoing.C.pp_write_error e
                        ) >>= fun continue ->
                        if continue then loop () else
                          Socket.Stream.Tcp.shutdown_write remote
                      in
                      loop ()
                    in
                    Lwt.join [ a_t; b_t ]
                ) (fun () -> Socket.Stream.Tcp.close remote)
          ) (fun () -> Tcp.close flow)
      in
      Some f
    in
    Lwt.return listeners

  let handle ~dst:(ip, port) ~t =
    match port, t.http, t.https with
    | 80, Some h, _ -> Some (http ~dst:ip ~t h)
    | 443, _, Some h ->
      if Exclude.matches ip None t.exclude
      then None
      else Some (https ~dst:ip h)
    | _, _, _ -> None

end
