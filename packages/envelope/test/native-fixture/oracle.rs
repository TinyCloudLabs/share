use std::{env, fs};

use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
    ssi::dids::AnyDidMethod,
};
use tinycloud_core::util::DelegationInfo;

fn text<'a>(value: &'a serde_json::Value, pointer: &str) -> &'a str {
    value.pointer(pointer).and_then(|v| v.as_str()).unwrap_or_else(|| panic!("missing {pointer}"))
}

fn canonical_millis(value: time::OffsetDateTime) -> String {
    assert_eq!(value.offset(), time::UtcOffset::UTC, "authority time must be UTC");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(), value.month() as u8, value.day(), value.hour(), value.minute(),
        value.second(), value.millisecond(),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const FIXTURE_TIME: i64 = 1_861_920_000; // 2029-01-01T00:00:00Z
    let fixture_time = time::OffsetDateTime::from_unix_timestamp(FIXTURE_TIME)?;
    let path = env::args().nth(1).expect("vector path");
    let vector: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let root_value = text(&vector, "/envelope/delegation/issuerProofs/0/value");
    let root_cid: Cid = text(&vector, "/envelope/delegation/issuerProofs/0/cid").parse()?;
    let transported_proofs = vector.pointer("/envelope/delegation/issuerProofs")
        .and_then(|value| value.as_array()).expect("issuerProofs array");
    assert_eq!(transported_proofs.len(), 1, "fixture must contain the Cacao root only");
    let grant_value = text(&vector, "/envelope/delegation/grant/value");
    let grant_cid: Cid = text(&vector, "/envelope/delegation/grant/cid").parse()?;

    let (root, root_preimage) = TinyCloudDelegation::decode(root_value)?;
    let (grant, grant_preimage) = TinyCloudDelegation::decode(grant_value)?;
    assert!(matches!(root, TinyCloudDelegation::Cacao(_)), "root must be Cacao");
    assert!(matches!(grant, TinyCloudDelegation::Ucan(_)), "grant must be UCAN");
    assert_eq!(Cid::new_v1(0x55, Code::Blake3_256.digest(&root_preimage)), root_cid);
    assert_eq!(Cid::new_v1(0x55, Code::Blake3_256.digest(&grant_preimage)), grant_cid);

    match &root {
        TinyCloudDelegation::Cacao(cacao) => {
            cacao.verify().await?;
            assert!(cacao.payload().valid_at(&fixture_time), "Cacao time invalid at fixture instant");
        }
        _ => unreachable!(),
    }
    let grant_verification_method = match &grant {
        TinyCloudDelegation::Ucan(ucan) => {
            ucan.verify_signature(&AnyDidMethod::default()).await?;
            ucan.payload().validate_time(Some(FIXTURE_TIME as f64))?;
            ucan.payload().issuer.to_string()
        }
        _ => unreachable!(),
    };

    let root_info = DelegationInfo::try_from(root.clone())?;
    let grant_info = DelegationInfo::try_from(grant.clone())?;
    assert!(root_info.parents.is_empty(), "root Cacao unexpectedly cites a parent");
    assert_eq!(grant_info.parents, vec![root_cid], "grant proof is not the Cacao root");
    assert_eq!(grant_info.delegator, root_info.delegate, "session principal adjacency failed");
    let (signer_principal, fragment) = grant_verification_method.split_once('#')
        .expect("grant issuer must be the current SDK verification-method DID URL");
    assert_eq!(signer_principal, root_info.delegate, "grant issuer principal is not root audience");
    assert_eq!(fragment, signer_principal.strip_prefix("did:key:").expect("did:key signer"),
        "verification-method fragment is not the signer multibase");

    let root_expiry = root_info.expiry.expect("root expiry");
    let grant_expiry = grant_info.expiry.expect("grant expiry");
    assert!(grant_expiry <= root_expiry, "grant expiry broadens root");
    if let Some(root_nbf) = root_info.not_before {
        assert!(grant_info.not_before.is_some_and(|grant_nbf| grant_nbf >= root_nbf));
    }
    assert_eq!(grant_info.capabilities.len(), 1, "fixture grant must carry one capability");
    for child in &grant_info.capabilities {
        assert!(root_info.capabilities.iter().any(|parent| {
            child.resource.extends(&parent.resource)
                && child.ability == parent.ability
                && child.caveats == parent.caveats
        }), "grant capability is not attenuated from SIWE ReCap root: {child:?}");
    }
    let child = &grant_info.capabilities[0];
    let action = child.ability.to_string();
    let (service, _) = action.strip_prefix("tinycloud.").and_then(|value| value.split_once('/'))
        .expect("TinyCloud ability namespace");
    let resource = child.resource.to_string();
    let (space_id, path) = resource.split_once(&format!("/{service}/"))
        .expect("resource must contain its ability service and exact path");
    let effective_not_before = match (root_info.not_before, grant_info.not_before) {
        (Some(root), Some(grant)) => Some(root.max(grant)),
        (Some(root), None) => Some(root),
        (None, grant) => grant,
    };
    let proof_cids: Vec<String> = transported_proofs.iter().map(|proof|
        text(proof, "/cid").to_owned()).collect();
    assert_eq!(proof_cids, vec![root_cid.to_string()], "transport proof order differs from authority chain");

    let mut derived = serde_json::json!({
        "verification": "tinycloud-native-authority-v1",
        "ownerDid": root_info.delegator,
        "sessionPrincipalDid": signer_principal,
        "sessionVerificationMethod": grant_verification_method,
        "recipientDid": grant_info.delegate,
        "grantCid": grant_cid.to_string(),
        "proofCids": proof_cids,
        "scope": {
            "spaceId": space_id,
            "resource": { "kind": "exact", "path": path },
            "actions": [action],
        },
        "expiry": canonical_millis(grant_expiry),
    });
    if let Some(not_before) = effective_not_before {
        derived.as_object_mut().expect("derived object").insert(
            "notBefore".into(), serde_json::Value::String(canonical_millis(not_before)));
    }
    assert_eq!(&derived, vector.pointer("/nativeVerified").expect("nativeVerified object"),
        "checked-in atomic native result differs from cryptographically derived authority");

    // Regression guard: the equality above must cover every previously missed
    // semantic field, not merely signatures and chain adjacency.
    for (pointer, replacement) in [
        ("/nativeVerified/expiry", serde_json::json!("2096-10-02T07:06:39.000Z")),
        ("/nativeVerified/proofCids", serde_json::json!([])),
        ("/nativeVerified/scope/resource/kind", serde_json::json!("prefix")),
    ] {
        let mut mutated = vector.clone();
        *mutated.pointer_mut(pointer).expect("regression pointer") = replacement;
        assert_ne!(&derived, mutated.pointer("/nativeVerified").expect("mutated native output"),
            "native output mutation was not covered: {pointer}");
    }
    println!("recipient-did-v2 native fixture: complete authority chain verified");
    Ok(())
}
