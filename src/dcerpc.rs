//! DCE/RPC bind detection (tier T0, offline). Locates an MSRPC (ncacn) version
//! 5.0 Bind PDU in a TCP payload - whether DCE/RPC runs directly over TCP or
//! inside an SMB named pipe (the PDU bytes are present either way) - and reports
//! the bound interface UUID by name, flagging the ones that matter for lateral
//! movement (DRSUAPI / DCSync, SVCCTL, task scheduler, SPOOLSS / EFSRPC
//! coercion, NETLOGON). Structure parsing only; nothing is executed.

use crate::util::push_uniq;

const CAP: usize = 100;

fn uuid_str(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

/// A name (and risk note) for a well-known MSRPC interface UUID.
fn interface_name(uuid: &str) -> Option<&'static str> {
    Some(match uuid {
        "e3514235-4b06-11d1-ab04-00c04fc2dcd2" => "DRSUAPI (directory replication - DCSync)",
        "12345778-1234-abcd-ef00-0123456789ac" => "SAMR (account enumeration)",
        "12345778-1234-abcd-ef00-0123456789ab" => "LSARPC (LSA policy / secrets)",
        "12345678-1234-abcd-ef00-01234567cffb" => "NETLOGON (secure channel - Zerologon)",
        "367abb81-9844-35f1-ad32-98f038001003" => "SVCCTL (service control - remote exec)",
        "4b324fc8-1670-01d3-1278-5a47bf6ee188" => "SRVSVC (share enumeration)",
        "12345678-1234-abcd-ef00-0123456789ab" => "SPOOLSS (print - PrintNightmare / coerce)",
        "338cd001-2244-31f1-aaaa-900038001003" => "WINREG (remote registry)",
        "1ff70682-0a51-30e8-076d-740be8cee98b" => "ATSVC (task scheduler - remote exec)",
        "86d35949-83c9-4044-b424-db363231fd0c" => "ITaskSchedulerService (remote exec)",
        "c681d488-d850-11d0-8c52-00c04fd90f7e" => "EFSRPC (EFS - PetitPotam coerce)",
        "df1941c5-fe89-4e79-bf10-463657acf44d" => "EFSRPC/lsarpc (PetitPotam coerce)",
        "e1af8308-5d1f-11c9-91a4-08002b14a0fa" => "EPM (endpoint mapper)",
        "6bffd098-a112-3610-9833-46c3f87e345a" => "WKSSVC (workstation service)",
        "3919286a-b10c-11d0-9ba8-00c04fd92ef5" => "DSSETUP (domain info)",
        _ => return None,
    })
}

/// Scan a TCP payload for a DCE/RPC Bind PDU and report the bound interface.
pub fn scan(payload: &[u8], notes: &mut Vec<String>) {
    let mut i = 0usize;
    while i + 48 <= payload.len() {
        // Common header: rpc_vers=5, rpc_vers_minor=0, PTYPE=11 (bind),
        // pfc_flags, packed_drep[0]=0x10 (little-endian) on essentially all hosts.
        if payload[i] == 5 && payload[i + 1] == 0 && payload[i + 2] == 11 && payload[i + 4] == 0x10
        {
            // Abstract-syntax interface UUID sits at offset 32 of the Bind PDU.
            let uuid = uuid_str(&payload[i + 32..i + 48]);
            let note = match interface_name(&uuid) {
                Some(name) => format!("DCE/RPC bind: {name}"),
                None => format!("DCE/RPC bind: interface {uuid}"),
            };
            push_uniq(notes, note, CAP);
            // A single payload rarely carries two binds; keep scanning in case
            // of a coalesced/compound buffer, but step past this header.
            i += 48;
            continue;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal DCE/RPC Bind PDU whose abstract-syntax UUID is `uuid`
    // (first three fields little-endian, last eight bytes big-endian).
    fn bind(uuid: &[u8; 16]) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 5; // version
        p[1] = 0; // minor
        p[2] = 11; // PTYPE bind
        p[3] = 0x03; // flags: first + last fragment
        p[4] = 0x10; // data representation: little-endian
        p[8] = 48; // frag_length (LE low byte)
        p[24] = 1; // n_context_elem
        p[32..48].copy_from_slice(uuid);
        p
    }

    // samr: 12345778-1234-abcd-ef00-0123456789ac
    fn samr_uuid() -> [u8; 16] {
        [
            0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xac,
        ]
    }

    // drsuapi: e3514235-4b06-11d1-ab04-00c04fc2dcd2
    fn drsuapi_uuid() -> [u8; 16] {
        [
            0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2,
            0xdc, 0xd2,
        ]
    }

    #[test]
    fn names_samr_bind() {
        let mut notes = Vec::new();
        scan(&bind(&samr_uuid()), &mut notes);
        assert_eq!(notes, vec!["DCE/RPC bind: SAMR (account enumeration)"]);
    }

    #[test]
    fn flags_drsuapi_dcsync() {
        let mut notes = Vec::new();
        scan(&bind(&drsuapi_uuid()), &mut notes);
        assert!(notes
            .iter()
            .any(|n| n.contains("DRSUAPI") && n.contains("DCSync")));
    }

    #[test]
    fn finds_bind_inside_smb_write() {
        // A DCE/RPC bind embedded after some SMB2 WRITE bytes is still located.
        let mut buf = vec![0xFEu8, b'S', b'M', b'B'];
        buf.extend_from_slice(&[0u8; 60]);
        buf.extend_from_slice(&bind(&samr_uuid()));
        let mut notes = Vec::new();
        scan(&buf, &mut notes);
        assert!(notes.iter().any(|n| n.contains("SAMR")));
    }

    #[test]
    fn reports_unknown_uuid() {
        let mut uuid = [0u8; 16];
        uuid[0] = 0xaa;
        let mut notes = Vec::new();
        scan(&bind(&uuid), &mut notes);
        assert!(notes
            .iter()
            .any(|n| n.starts_with("DCE/RPC bind: interface ")));
    }

    #[test]
    fn ignores_non_rpc() {
        let mut notes = Vec::new();
        scan(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &mut notes);
        assert!(notes.is_empty());
    }
}
