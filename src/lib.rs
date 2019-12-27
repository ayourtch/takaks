extern crate byteorder;
extern crate crypto;
extern crate rand;
#[macro_use]
extern crate enum_primitive;
extern crate num;

/* TACACS+ client */
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use crypto::digest::Digest;
use crypto::md5::Md5;
use num::FromPrimitive;
use std::io::Write;
use std::str::from_utf8;

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]
    pub enum TacacsPacketType
    {
        TAC_PLUS_AUTHEN = 1,
        TAC_PLUS_AUTHOR = 2,
        TAC_PLUS_ACCT = 3
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]
    pub enum TacacsAuthenAction
    {
        TAC_PLUS_AUTHEN_LOGIN = 1,
        TAC_PLUS_AUTHEN_CHPASS = 2,
        TAC_PLUS_AUTHEN_SENDAUTH = 4
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]
    pub enum TacacsAuthenType
    {
        TAC_PLUS_AUTHEN_TYPE_ASCII = 1,
        TAC_PLUS_AUTHEN_TYPE_PAP = 2,
        TAC_PLUS_AUTHEN_TYPE_CHAP = 3,
        TAC_PLUS_AUTHEN_TYPE_ARAP = 4, // deprecated
        TAC_PLUS_AUTHEN_TYPE_MSCHAP = 5,
        TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 6
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]
    pub enum TacacsAuthenService
    {
        TAC_PLUS_AUTHEN_SVC_NONE = 0,
        TAC_PLUS_AUTHEN_SVC_LOGIN = 1,
        TAC_PLUS_AUTHEN_SVC_ENABLE = 2,
        TAC_PLUS_AUTHEN_SVC_PPP = 3,
        TAC_PLUS_AUTHEN_SVC_ARAP = 4,
        TAC_PLUS_AUTHEN_SVC_PT = 5,
        TAC_PLUS_AUTHEN_SVC_RCMD = 6,
        TAC_PLUS_AUTHEN_SVC_X25 = 7,
        TAC_PLUS_AUTHEN_SVC_NASI = 8,
        TAC_PLUS_AUTHEN_SVC_FWPROXY = 9,
    }
}

fn write_be32(out: &mut Vec<u8>, val: u32) {
    out.write(&[0, 0, 0, 0]).unwrap();
    let len = out.len();
    BigEndian::write_u32(&mut out[len - 4..len], val);
}
fn write_be16(out: &mut Vec<u8>, val: u16) {
    out.write(&[0, 0]).unwrap();
    let len = out.len();
    BigEndian::write_u16(&mut out[len - 2..len], val);
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
struct TacacsPacket {
    pub majorVersion: u8,
    pub minorVersion: u8,
    pub packetType: TacacsPacketType,
    pub seq_no: u8,
    pub flags: u8,
    pub session_id: u32,
    pub data: Vec<u8>,
    pub IsSane: bool,     // false;
    pub IsTooShort: bool, // = true;
}

impl TacacsPacket {
    fn version(&self) -> u8 {
        (((self.majorVersion as u8) & 0xc) << 4) + (self.minorVersion as u8 & 0xf)
    }

    fn getSubsequentHash(
        hasher: &mut crypto::md5::Md5,
        session_id: u32,
        key: &str,
        version: u8,
        seq_no: u8,
        prev_hash: &[u8; 16],
    ) -> [u8; 16] {
        let mut buf: Vec<u8> = vec![];
        write_be32(&mut buf, session_id);
        buf.write(key.as_bytes()).unwrap();
        buf.write(&[version, seq_no]).unwrap();
        buf.write(prev_hash).unwrap();

        hasher.reset();
        hasher.input(&buf);

        let mut out: [u8; 16] = [0; 16];
        hasher.result(&mut out);
        out
    }

    fn getInitialHash(
        hasher: &mut crypto::md5::Md5,
        session_id: u32,
        key: &str,
        version: u8,
        seq_no: u8,
    ) -> [u8; 16] {
        let mut buf: Vec<u8> = vec![];
        write_be32(&mut buf, session_id);
        buf.write(key.as_bytes()).unwrap();
        buf.write(&[version, seq_no]).unwrap();

        hasher.reset();
        hasher.input(&buf);

        let mut out: [u8; 16] = [0; 16];
        hasher.result(&mut out);
        out
    }

    fn getMd5Pad(session_id: u32, key: &str, version: u8, seq_no: u8, len: usize) -> Vec<u8> {
        let mut hasher = Md5::new();
        let mut remaining_len = len;
        let initial_hash =
            TacacsPacket::getInitialHash(&mut hasher, session_id, key, version, seq_no);
        let initial_len = if remaining_len > initial_hash.len() {
            initial_hash.len()
        } else {
            remaining_len
        };
        let mut out = vec![];
        let current_offset = 0;
        let current_len = 0;
        let mut previous_hash = initial_hash.clone();
        let mut current_hash: [u8; 16] = [0; 16];
        let _ = current_hash;

        out.write(&initial_hash[0..initial_len]).unwrap();
        if remaining_len <= initial_len {
            return out;
        }
        remaining_len = remaining_len - initial_len;
        loop {
            current_hash = TacacsPacket::getSubsequentHash(
                &mut hasher,
                session_id,
                key,
                version,
                seq_no,
                &previous_hash,
            );
            let len = if remaining_len > current_hash.len() {
                current_hash.len()
            } else {
                remaining_len
            };
            out.write(&current_hash[0..len]).unwrap();
            previous_hash = current_hash.clone();
            remaining_len = remaining_len - len;
            if remaining_len <= 0 {
                break;
            }
        }
        return out;
    }

    fn from_TacacsPacket(req: &TacacsPacket, body: &Vec<u8>) -> TacacsPacket {
        TacacsPacket {
            majorVersion: req.majorVersion,
            minorVersion: req.minorVersion,
            packetType: req.packetType.clone(),
            seq_no: req.seq_no.clone() + 1,
            flags: req.flags.clone(),
            session_id: req.session_id.clone(),
            data: body.clone(),
            IsSane: false,
            IsTooShort: true,
        }
    }
    fn from_parts(
        packet_type: TacacsPacketType,
        a_session_id: u32,
        seq: u8,
        body: &Vec<u8>,
        flags: u8,
    ) -> TacacsPacket {
        TacacsPacket {
            majorVersion: 12,
            minorVersion: 0, // 1
            packetType: packet_type.clone(),
            seq_no: seq,
            flags: flags,
            session_id: a_session_id,
            data: body.clone(),
            IsSane: false,
            IsTooShort: true,
        }
    }

    fn from_bytes(buf: &Vec<u8>, secret: &str) -> Option<TacacsPacket> {
        if buf.len() < 12 {
            return None; // we did not get the packet yet, do not close
        }

        let majorVersion = buf[0] >> 4;
        let minorVersion = buf[0] & 0xf;
        let packetType_res = TacacsPacketType::from_u8(buf[1]);
        let seq_no = buf[2];
        let flags = buf[3];
        let session_id = BigEndian::read_u32(&buf[4..8]);
        let len = BigEndian::read_u32(&buf[8..12]) as usize;
        if majorVersion != 0xc {
            println!("Wrong majorVersion: {}", majorVersion);
            return None;
        }
        if (minorVersion | 1) != 1 {
            println!("Wrong minorVersion: {}", minorVersion);
            return None;
        }

        if packetType_res.is_none() {
            println!("packetType unknown: {}", buf[1]);
            return None;
        }
        let packetType = packetType_res.unwrap();
        if buf.len() < 12 + len {
            println!(
                "Buffer len too short - {} vs {} expected as per packet",
                buf.len(),
                12 + len
            );
            return None;
        }

        let mut data: Vec<u8> = vec![];
        if (flags & 1) == 1 {
            // cleartext packet
            data.write(&buf[12..buf.len()]).unwrap();
        } else {
            // encrypted packet body
            data = TacacsPacket::getMd5Pad(session_id, secret, buf[0], seq_no, len);
            for i in 0..len {
                data[i] = data[i] ^ buf[12 + i];
            }
        }
        let tp = TacacsPacket {
            majorVersion: majorVersion,
            minorVersion: minorVersion,
            packetType: packetType,
            seq_no: seq_no,
            flags: flags,
            session_id: session_id,
            data: data,
            IsSane: true,
            IsTooShort: false,
        };
        Some(tp)
    }

    pub fn as_bytes(&self, secret: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        let out_flags = if secret == "" {
            self.flags | 1
        } else {
            self.flags & 0xfe
        };
        out.write(&[
            self.version(),
            self.packetType.clone() as u8,
            self.seq_no,
            out_flags,
        ])
        .unwrap();
        write_be32(&mut out, self.session_id);
        write_be32(&mut out, self.data.len() as u32);
        out.write(&self.data).unwrap();
        if secret != "" {
            let pad = TacacsPacket::getMd5Pad(
                self.session_id,
                secret,
                self.version(),
                self.seq_no,
                self.data.len(),
            );
            for i in 0..self.data.len() {
                out[12 + i] = out[12 + i] ^ pad[i];
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TacacsPacketBodyAuthenStart {
    pub action: TacacsAuthenAction,
    pub priv_lvl: u8,
    pub authen_type: TacacsAuthenType,
    pub authen_service: TacacsAuthenService,
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub data: String,
}

impl TacacsPacketBodyAuthenStart {
    fn from_bytes(raw: Vec<u8>) -> Option<TacacsPacketBodyAuthenStart> {
        let action_res = TacacsAuthenAction::from_u8(raw[0]);
        let priv_lvl = raw[1];
        let authen_type_res = TacacsAuthenType::from_u8(raw[2]);
        let authen_service_res = TacacsAuthenService::from_u8(raw[3]);
        if action_res.is_none() || authen_type_res.is_none() || authen_service_res.is_none() {
            return None;
        }
        let action = action_res.unwrap();
        let authen_type = authen_type_res.unwrap();
        let authen_service = authen_service_res.unwrap();

        let user_len = raw[4] as usize;
        let mut user = "".to_string();

        let port_len = raw[5] as usize;
        let mut port = "".to_string();

        let rem_addr_len = raw[6] as usize;
        let mut rem_addr = "".to_string();

        let data_len = raw[7] as usize;
        let mut data = "".to_string();

        let mut index: usize = 8;
        if user_len > 0 {
            user.push_str(
                from_utf8(&raw[index..index + user_len]).unwrap_or("----ERROR DECODING----"),
            );
            index = index + user_len;
        }
        if port_len > 0 {
            port.push_str(
                from_utf8(&raw[index..index + port_len]).unwrap_or("----ERROR DECODING----"),
            );
            index = index + port_len;
        }
        if rem_addr_len > 0 {
            rem_addr.push_str(
                from_utf8(&raw[index..index + rem_addr_len]).unwrap_or("----ERROR DECODING----"),
            );
            index = index + rem_addr_len;
        }
        if data_len > 0 {
            data.push_str(
                from_utf8(&raw[index..index + data_len]).unwrap_or("----ERROR DECODING----"),
            );
            index = index + data_len;
        }
        let _ = index;

        let out = TacacsPacketBodyAuthenStart {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            data,
        };
        Some(out)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        out.write(&[
            self.action.clone() as u8,
            self.priv_lvl,
            self.authen_type.clone() as u8,
            self.authen_service.clone() as u8,
            self.user.len() as u8,
            self.port.len() as u8,
            self.rem_addr.len() as u8,
            self.data.len() as u8,
        ])
        .unwrap();
        out.write(&self.user.clone().as_bytes()).unwrap();
        out.write(&self.port.clone().as_bytes()).unwrap();
        out.write(&self.rem_addr.clone().as_bytes()).unwrap();
        out.write(&self.data.clone().as_bytes()).unwrap();
        out
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TacacsPacketBodyAuthenContinue {
    pub user_msg: String,
    pub data: String,
    pub flags: u8,
}

impl TacacsPacketBodyAuthenContinue {
    fn from_bytes(raw: &Vec<u8>) -> Option<TacacsPacketBodyAuthenContinue> {
        let user_msg_len = BigEndian::read_u16(&raw[0..2]) as usize;
        let data_len = BigEndian::read_u16(&raw[2..4]) as usize;
        let mut user_msg = "".to_string();
        let mut data = "".to_string();
        let flags = raw[4];
        let mut index: usize = 5;
        if user_msg_len > 0 {
            user_msg.push_str(
                from_utf8(&raw[index..index + user_msg_len]).unwrap_or("---- ERROR DECODING ----"),
            );
            index = index + user_msg_len;
        }
        if data_len > 0 {
            data.push_str(
                from_utf8(&raw[index..index + data_len]).unwrap_or("---- ERROR DECODING ----"),
            );
            index = index + data_len;
        }
        let _ = index;
        let out = TacacsPacketBodyAuthenContinue {
            user_msg,
            data,
            flags,
        };
        Some(out)
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        write_be16(&mut out, self.user_msg.len() as u16);
        write_be16(&mut out, self.data.len() as u16);
        out.write(&[self.flags]).unwrap();
        out.write(&self.user_msg.clone().as_bytes()).unwrap();
        out.write(&self.data.clone().as_bytes()).unwrap();
        out
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]

    pub enum TacacsAuthenReplyStatus
    {
        TAC_PLUS_AUTHEN_STATUS_PASS = 1,
        TAC_PLUS_AUTHEN_STATUS_FAIL = 2,
        TAC_PLUS_AUTHEN_STATUS_GETDATA = 3,
        TAC_PLUS_AUTHEN_STATUS_GETUSER = 4,
        TAC_PLUS_AUTHEN_STATUS_GETPASS = 5,
        TAC_PLUS_AUTHEN_STATUS_RESTART = 6,
        TAC_PLUS_AUTHEN_STATUS_ERROR = 7,
        TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]
    pub enum TacacsAuthenReplyFlags
    {
        TAC_PLUS_REPLY_FLAG_NOECHO = 1,
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TacacsPacketBodyAuthenReply {
    pub status: TacacsAuthenReplyStatus,
    pub flags: u8,
    pub server_msg: String,
    pub data: String,
}

impl TacacsPacketBodyAuthenReply {
    fn from_bytes(raw: &Vec<u8>) -> Option<TacacsPacketBodyAuthenReply> {
        let status_res = TacacsAuthenReplyStatus::from_u8(raw[0]);
        if status_res.is_none() {
            return None;
        }
        let status = status_res.unwrap();
        let flags = raw[1];
        let mut server_msg = "".to_string();
        let mut data = "".to_string();

        let server_msg_len = BigEndian::read_u16(&raw[2..4]) as usize;
        let data_len = BigEndian::read_u16(&raw[4..6]) as usize;
        let mut index = 6;
        if server_msg_len > 0 {
            server_msg.push_str(
                from_utf8(&raw[index..index + server_msg_len])
                    .unwrap_or("---- ERROR DECODING ----"),
            );
            index = index + server_msg_len;
        }
        if data_len > 0 {
            data.push_str(
                from_utf8(&raw[index..index + data_len]).unwrap_or("---- ERROR DECODING ----"),
            );
            index = index + data_len;
        }
        let _ = index;
        let out = TacacsPacketBodyAuthenReply {
            status,
            flags,
            server_msg,
            data,
        };
        Some(out)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        out.write(&[self.status.clone() as u8, self.flags]).unwrap();
        write_be16(&mut out, self.server_msg.len() as u16);
        write_be16(&mut out, self.data.len() as u16);
        out.write(&self.server_msg.clone().as_bytes()).unwrap();
        out.write(&self.data.clone().as_bytes()).unwrap();
        out
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]

    pub enum TacacsAuthenMethod
    {
        TAC_PLUS_AUTHEN_METH_NOT_SET = 0,
        TAC_PLUS_AUTHEN_METH_NONE = 1,
        TAC_PLUS_AUTHEN_METH_KRB5 = 2,
        TAC_PLUS_AUTHEN_METH_LINE = 3,
        TAC_PLUS_AUTHEN_METH_ENABLE = 4,
        TAC_PLUS_AUTHEN_METH_LOCAL = 5,
        TAC_PLUS_AUTHEN_METH_TACACSPLUS = 6,
        TAC_PLUS_AUTHEN_METH_GUEST = 8,
        TAC_PLUS_AUTHEN_METH_RADIUS = 0x10,
        TAC_PLUS_AUTHEN_METH_KRB4 = 0x11,
        TAC_PLUS_AUTHEN_METH_RCMD = 0x20
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TacacsPacketBodyAuthorRequest {
    pub authen_method: TacacsAuthenMethod,
    pub priv_lvl: u8,
    pub authen_type: TacacsAuthenType,
    pub authen_service: TacacsAuthenService,
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub args: Vec<String>,
}

impl TacacsPacketBodyAuthorRequest {
    fn from_bytes(raw: &Vec<u8>) -> Option<TacacsPacketBodyAuthorRequest> {
        let authen_method_res = TacacsAuthenMethod::from_u8(raw[0]);
        let priv_lvl = raw[1];
        let authen_type_res = TacacsAuthenType::from_u8(raw[2]);
        let authen_service_res = TacacsAuthenService::from_u8(raw[3]);
        let user_len = raw[4] as usize;
        let port_len = raw[5] as usize;
        let rem_addr_len = raw[6] as usize;
        let arg_cnt = raw[7] as usize;
        let mut per_arg_len: Vec<u8> = vec![];

        if authen_method_res.is_none() || authen_type_res.is_none() || authen_service_res.is_none()
        {
            return None;
        }
        let authen_method = authen_method_res.unwrap();
        let authen_type = authen_type_res.unwrap();
        let authen_service = authen_service_res.unwrap();

        per_arg_len.write(&raw[8..8 + arg_cnt]).unwrap();

        let mut user = "".to_string();
        let mut port = "".to_string();
        let mut rem_addr = "".to_string();
        let mut args: Vec<String> = vec![];

        let mut index = 8 + arg_cnt;
        if user_len > 0 {
            user.push_str(
                from_utf8(&raw[index..index + user_len]).unwrap_or("---- DECODE FAILED ----"),
            );
            index = index + user_len;
        }
        if port_len > 0 {
            port.push_str(
                from_utf8(&raw[index..index + port_len]).unwrap_or("---- DECODE FAILED ----"),
            );
            index = index + port_len;
        }
        if rem_addr_len > 0 {
            rem_addr.push_str(
                from_utf8(&raw[index..index + rem_addr_len]).unwrap_or("---- DECODE FAILED ----"),
            );
            index = index + rem_addr_len;
        }
        for i in 0..arg_cnt {
            let mut argX = "".to_string();
            if per_arg_len[i] > 0 {
                argX.push_str(
                    from_utf8(&raw[index..index + per_arg_len[i] as usize])
                        .unwrap_or("---- DECODE FAILED ----"),
                );
                index = index + per_arg_len[i] as usize;
            }
            args.push(argX);
        }
        let out = TacacsPacketBodyAuthorRequest {
            authen_method,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            args,
        };
        Some(out)
    }
}

enum_from_primitive! {
#[derive(Clone, Debug, PartialEq, PartialOrd)]
    pub enum TacacsAuthorReplyStatus
    {
        TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 1,
        TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 2,
        TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10,
        TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11,
        TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct TacacsPacketBodyAuthorReply {
    pub status: TacacsAuthorReplyStatus,
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}

impl TacacsPacketBodyAuthorReply {
    fn from_bytes(raw: &Vec<u8>) -> Option<TacacsPacketBodyAuthorReply> {
        let status_res = TacacsAuthorReplyStatus::from_u8(raw[0]);
        if status_res.is_none() {
            return None;
        }
        let num_args = raw[1] as usize;
        let status = status_res.unwrap();
        let mut server_msg = "".to_string();
        let mut data = "".to_string();

        let server_msg_len = BigEndian::read_u16(&raw[2..4]) as usize;
        let data_len = BigEndian::read_u16(&raw[4..6]) as usize;
        let mut per_arg_len: Vec<u8> = vec![];

        per_arg_len.write(&raw[6..6 + num_args]).unwrap();

        let mut index = 6 + num_args;

        if server_msg_len > 0 {
            server_msg.push_str(
                from_utf8(&raw[index..index + server_msg_len])
                    .unwrap_or("---- ERROR DECODING ----"),
            );
            index = index + server_msg_len;
        }
        if data_len > 0 {
            data.push_str(
                from_utf8(&raw[index..index + data_len]).unwrap_or("---- ERROR DECODING ----"),
            );
            index = index + data_len;
        }

        let mut args: Vec<String> = vec![];
        for i in 0..num_args {
            let mut argX = "".to_string();
            if per_arg_len[i] > 0 {
                argX.push_str(
                    from_utf8(&raw[index..index + per_arg_len[i] as usize])
                        .unwrap_or("---- DECODE FAILED ----"),
                );
                index = index + per_arg_len[i] as usize;
            }
            args.push(argX);
        }
        let out = TacacsPacketBodyAuthorReply {
            status,
            server_msg,
            data,
            args,
        };
        Some(out)
    }
    fn as_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = vec![];
        out.write(&[self.status.clone() as u8, self.args.len() as u8])
            .unwrap();
        write_be16(&mut out, self.server_msg.len() as u16);
        write_be16(&mut out, self.data.len() as u16);

        let mut per_arg_len: Vec<u8> = vec![];
        for i in 0..self.args.len() {
            per_arg_len.push(self.args[i].len() as u8);
        }
        out.write(&per_arg_len).unwrap();
        out.write(self.server_msg.clone().as_bytes()).unwrap();
        out.write(self.data.clone().as_bytes()).unwrap();
        for i in 0..self.args.len() {
            out.write(&self.args[i].clone().as_bytes()).unwrap();
        }
        out
    }
}

use std::net::TcpStream;

#[derive(Debug)]
pub struct TacacsPlusClient {
    pub server_addr: String,
    pub tacacs_secret: String,
    pub debug: i32,
}

impl TacacsPlusClient {
    pub fn new(a_server_addr: &str, a_secret: &str) -> Result<TacacsPlusClient, std::io::Error> {
        use std::io::prelude::*;

        let target_addr = if a_server_addr.contains(":") {
            format!("{}", a_server_addr)
        } else {
            format!("{}:49", a_server_addr)
        };

        let out = TacacsPlusClient {
            server_addr: target_addr.clone(),
            tacacs_secret: a_secret.to_string(),
            debug: 0,
        };
        Ok(out)
    }

    fn SomeSleep(&mut self) {
        use std::{thread, time};

        let sleep_time = time::Duration::from_millis(100);
        let now = time::Instant::now();

        thread::sleep(sleep_time);
    }

    fn SendReceive(
        &mut self,
        stream: &mut TcpStream,
        msg: &Vec<u8>,
    ) -> Result<Vec<u8>, std::io::Error> {
        use std::io::Read;
        let mut readbuf: [u8; 2048] = [0; 2048];
        let written = stream.write(&msg)?;

        // self.SomeSleep();
        let nread = stream.read(&mut readbuf)?;
        let out = readbuf[0..nread].to_vec();
        if self.debug > 0 {
            println!("Nread: {}, res: {:?}", nread, &out);
        }
        return Ok(out);
    }
    fn rnd32(&mut self) -> u32 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let n2: u32 = rng.gen();
        return n2;
    }

    pub fn AuthenticateUser(
        &mut self,
        user_name: &str,
        user_pass: &str,
    ) -> Result<bool, std::io::Error> {
        let session_ID = self.rnd32();
        if self.debug > 0 {
            println!("Connecting to {}...", &self.server_addr);
        }
        let mut stream = TcpStream::connect(&self.server_addr)?;
        if self.debug > 0 {
            println!("Connected to {}", &self.server_addr);
        }
        let req_body = TacacsPacketBodyAuthenStart {
            user: user_name.to_string(),
            priv_lvl: 1,
            rem_addr: "127.0.0.1".to_string(),
            data: "".to_string(),
            action: TacacsAuthenAction::TAC_PLUS_AUTHEN_LOGIN,
            port: "a3s".to_string(),
            authen_type: TacacsAuthenType::TAC_PLUS_AUTHEN_TYPE_ASCII,
            authen_service: TacacsAuthenService::TAC_PLUS_AUTHEN_SVC_LOGIN,
        };
        let req = TacacsPacket::from_parts(
            TacacsPacketType::TAC_PLUS_AUTHEN,
            session_ID,
            1,
            &req_body.to_bytes(),
            0,
        );
        if self.debug > 0 {
            println!("Request: '{:?}'", &req);
        }
        let msg = req.as_bytes(&self.tacacs_secret);

        let recvd_res = self.SendReceive(&mut stream, &msg);
        if self.debug > 0 {
            println!("Received MSG: {:?}", &recvd_res);
        }
        if !recvd_res.is_ok() {
            use std::io::{Error, ErrorKind};
            return Err(Error::new(
                ErrorKind::NotFound,
                format!(
                    "Did not receive the reply from TACACS+ server... error: {:?}",
                    &recvd_res
                ),
            ));
        }
        let recvd = recvd_res.unwrap();
        let reply_res = TacacsPacket::from_bytes(&recvd, &self.tacacs_secret);
        if self.debug > 0 {
            println!("Reply: {:?}", &reply_res);
        }
        let reply_body_res = TacacsPacketBodyAuthenReply::from_bytes(&reply_res.unwrap().data);
        if self.debug > 0 {
            println!("Reply body: {:?}", &reply_body_res);
        }
        if reply_body_res.is_none() {
            use std::io::{Error, ErrorKind};
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("Could not decrypt the reply... bad secret?"),
            ));
        }

        let reply_body = reply_body_res.unwrap();
        if reply_body.status == TacacsAuthenReplyStatus::TAC_PLUS_AUTHEN_STATUS_GETPASS {
            let req_body1 = TacacsPacketBodyAuthenContinue {
                user_msg: user_pass.to_string(),
                data: "".to_string(),
                flags: 0,
            };
            let req1 = TacacsPacket::from_parts(
                TacacsPacketType::TAC_PLUS_AUTHEN,
                session_ID,
                3,
                &req_body1.to_bytes(),
                0,
            );
            let msg1 = req1.as_bytes(&self.tacacs_secret);

            let recvd1_res = self.SendReceive(&mut stream, &msg1);
            if self.debug > 0 {
                println!("Received1 MSG: {:?}", &recvd1_res);
            }
            let recvd1 = recvd1_res.unwrap();
            let reply1_res = TacacsPacket::from_bytes(&recvd1, &self.tacacs_secret);
            if self.debug > 0 {
                println!("Reply: {:?}", &reply1_res);
            }
            let reply1_body_res =
                TacacsPacketBodyAuthenReply::from_bytes(&reply1_res.unwrap().data);
            if self.debug > 0 {
                println!("Reply body: {:?}", &reply1_body_res);
            }
            let reply1_body = reply1_body_res.unwrap();
            let outcome =
                reply1_body.status == TacacsAuthenReplyStatus::TAC_PLUS_AUTHEN_STATUS_PASS;
            return Ok(outcome);
        }
        Ok(false)
    }
}

/*
fn main() {
    let mut tc = TacacsPlusClient::new("192.168.42.128", "cisco123").unwrap();
    let res = tc.AuthenticateUser("aytest", "cisco123");
    println!("Auth result: {:?}", res);
}
*/
