use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;

fn jcs(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(if *v { "true" } else { "false" }.into()),
        Value::Number(v) => {
            if v.as_i64().is_none() && v.as_u64().is_none() {
                return Err("fixture verifier only accepts safe integer JSON numbers".into());
            }
            Ok(v.to_string())
        }
        Value::String(v) => serde_json::to_string(v).map_err(|e| e.to_string()),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(jcs)
                .collect::<Result<Vec<_>>>()?
                .join(",")
        )),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by_key(|key| key.encode_utf16().collect::<Vec<_>>());
            let mut members = Vec::with_capacity(keys.len());
            for key in keys {
                members.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|e| e.to_string())?,
                    jcs(object.get(key).ok_or("missing object member")?)?
                ));
            }
            Ok(format!("{{{}}}", members.join(",")))
        }
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
fn digest(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sha256(bytes))
}
fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}
fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing object field {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field {key}"))
}
fn b64(value: &Value, key: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text(value, key).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{key}: {e}"))
}
fn assert_ok(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
fn base58_decode(input: &str) -> Result<Vec<u8>> {
    let mut big = vec![0u8];
    for byte in input.bytes() {
        let digit = B58
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("bad base58")? as u32;
        let mut carry = digit;
        for value in big.iter_mut().rev() {
            let next = (*value as u32) * 58 + carry;
            *value = (next & 255) as u8;
            carry = next >> 8;
        }
        while carry != 0 {
            big.insert(0, (carry & 255) as u8);
            carry >>= 8;
        }
    }
    let zeros = input.bytes().take_while(|byte| *byte == b'1').count();
    let mut result = vec![0u8; zeros];
    result.extend(big.into_iter().skip_while(|byte| *byte == 0));
    Ok(result)
}
fn did_key_bytes(did: &str) -> Result<[u8; 32]> {
    let encoded = did.strip_prefix("did:key:z").ok_or("not did:key")?;
    let value = base58_decode(encoded)?;
    assert_ok(
        value.len() == 34 && value[0] == 0xed && value[1] == 1,
        "bad Ed25519 did:key multicodec",
    )?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&value[2..]);
    assert_ok(
        raw != [0u8; 32] && !(raw[0] == 1 && raw[1..] == [0u8; 31]),
        "small-order Ed25519 key",
    )?;
    Ok(raw)
}
fn cid(bytes: &[u8]) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut input = vec![1, 0x55, 0x12, 0x20];
    input.extend(sha256(bytes));
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut out = String::from("b");
    for byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}
fn verify_artifact(
    artifact: &Value,
    artifact_name: &str,
    domains: &Map<String, Value>,
    enrollment: &Value,
) -> Result<()> {
    let domain = text(artifact, "domain")?;
    let registered_domain = domains
        .get(artifact_name)
        .and_then(Value::as_str)
        .ok_or("missing domain")?;
    assert_ok(domain == registered_domain, "registry domain mismatch")?;
    let message = artifact.get("message").ok_or("missing artifact message")?;
    let canonical = jcs(message)?;
    assert_ok(canonical == text(artifact, "jcs")?, "JCS mismatch")?;
    let signed = [domain.as_bytes(), canonical.as_bytes()].concat();
    assert_ok(
        digest(canonical.as_bytes()) == text(artifact, "messageDigest")?,
        "message digest mismatch",
    )?;
    assert_ok(
        digest(&signed) == text(artifact, "signedBytesDigest")?,
        "signed bytes digest mismatch",
    )?;
    let signature_object = object(artifact, "signature")?;
    let signature_value = signature_object
        .get("value")
        .and_then(Value::as_str)
        .ok_or("signature value")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_value)
        .map_err(|e| e.to_string())?;
    assert_ok(signature.len() == 64, "signature length")?;
    assert_ok(
        digest(&signature) == text(artifact, "signatureDigest")?,
        "signature digest mismatch",
    )?;
    let signer = text(artifact, "signerDid")?;
    let public = if artifact_name == "inviteAuthorization"
        || artifact_name == "policyChallenge"
        || artifact_name == "policySession"
    {
        let raw = b64(enrollment, "invitationPublicKey")?;
        raw.try_into()
            .map_err(|_| "node public key length".to_string())?
    } else {
        did_key_bytes(signer)?
    };
    let key = VerifyingKey::from_bytes(&public).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
    key.verify_strict(&signed, &sig)
        .map_err(|e| format!("{artifact_name}: {e}"))?;
    Ok(())
}
fn verify(root: &Path) -> Result<()> {
    let vector_dir = root.join("test/vectors/email-claim-v1");
    let spec_dir = root.join("specs/email-claim-v1");
    let manifest = read_json(&vector_dir.join("manifest.json"))?;
    let manifest_core = {
        let mut value = manifest.clone();
        value
            .as_object_mut()
            .ok_or("manifest object")?
            .remove("manifestDigest");
        value
    };
    assert_ok(
        digest(jcs(&manifest_core)?.as_bytes()) == text(&manifest, "manifestDigest")?,
        "manifest digest mismatch",
    )?;
    let files = object(&manifest, "files")?;
    for (name, expected) in files {
        let path = if name == "README.md" || name == "domains.json" || name == "schemas.json" {
            spec_dir.join(name)
        } else {
            vector_dir.join(name)
        };
        assert_ok(
            digest(&fs::read(path).map_err(|e| e.to_string())?)
                == expected.as_str().ok_or("file digest")?,
            &format!("file digest mismatch: {name}"),
        )?;
    }
    let domains = read_json(&spec_dir.join("domains.json"))?;
    let schemas = read_json(&spec_dir.join("schemas.json"))?;
    assert_ok(
        domains
            .get("domains")
            .and_then(Value::as_object)
            .and_then(|d| d.get("envelope"))
            .and_then(Value::as_str)
            .map(|d| d.ends_with('\0'))
            .unwrap_or(false),
        "envelope domain missing",
    )?;
    assert_ok(schemas.get("schemas").is_some(), "schemas missing")?;
    let positive = read_json(&vector_dir.join("positive.json"))?;
    for scenario in array(&positive, "scenarios")? {
        let policy_bytes = b64(scenario, "policyBytes")?;
        assert_ok(
            !String::from_utf8_lossy(&policy_bytes).contains("policyCid"),
            "policy self-reference",
        )?;
        assert_ok(
            cid(&policy_bytes) == text(scenario, "policyCid")?,
            "policy CID mismatch",
        )?;
        let sealed = b64(scenario, "sealedBlob")?;
        assert_ok(
            cid(&sealed) == text(scenario, "shareCid")?,
            "share CID mismatch",
        )?;
        let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
        let artifacts = array(scenario, "artifacts")?;
        let domains_map = object(&domains, "domains")?;
        for artifact in artifacts {
            let name = text(artifact, "name")?;
            verify_artifact(artifact, name, domains_map, enrollment)?;
        }
        let preimages = object(scenario, "preimages")?;
        for (name, preimage) in preimages {
            let body = preimage.get("body").ok_or("preimage body")?;
            let canonical = jcs(body)?;
            assert_ok(
                canonical == text(preimage, "jcs")?
                    && digest(canonical.as_bytes()) == text(preimage, "digest")?,
                &format!("preimage mismatch: {name}"),
            )?;
        }
        let signed_preimages = object(scenario, "signedBytePreimages")?;
        for artifact in artifacts {
            let name = text(artifact, "name")?;
            let frozen = signed_preimages
                .get(name)
                .ok_or("signed preimage missing")?;
            assert_ok(
                text(frozen, "domain")? == text(artifact, "domain")?
                    && text(frozen, "jcs")? == text(artifact, "jcs")?
                    && text(frozen, "digest")? == text(artifact, "signedBytesDigest")?,
                "signed preimage drift",
            )?;
        }
    }
    Ok(())
}
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../");
    verify(&root).unwrap_or_else(|error| panic!("email-claim-v1 rust verifier failed: {error}"));
    println!("email-claim-v1 rust verifier: PASS");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cross_language_fixture() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../");
        verify(&root).unwrap();
    }
}
