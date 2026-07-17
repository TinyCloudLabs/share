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
            if v.to_string() == "-0"
                || v.as_i64().is_none() && v.as_u64().is_none()
                || v.as_i64()
                    .is_some_and(|value| value.unsigned_abs() > 9_007_199_254_740_991)
                || v.as_u64()
                    .is_some_and(|value| value > 9_007_199_254_740_991)
            {
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
fn map_text<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}
fn map_object<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing object field {key}"))
}
fn map_array<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field {key}"))
}
fn b64(value: &Value, key: &str) -> Result<Vec<u8>> {
    let encoded = text(value, key).map_err(|e| e.to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("{key}: {e}"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(format!("{key}: non-canonical base64url"));
    }
    Ok(decoded)
}
fn b64_map(value: &Map<String, Value>, key: &str) -> Result<Vec<u8>> {
    let encoded = map_text(value, key)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("{key}: {e}"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(format!("{key}: non-canonical base64url"));
    }
    Ok(decoded)
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
    let key = VerifyingKey::from_bytes(&raw).map_err(|e| e.to_string())?;
    assert_ok(!key.is_weak(), "small-order Ed25519 key")?;
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
    assert_ok(
        URL_SAFE_NO_PAD.encode(&signature) == signature_value,
        "non-canonical signature encoding",
    )?;
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
fn verify_signature_core(artifact: &Value, artifact_name: &str, enrollment: &Value) -> Result<()> {
    let domain = text(artifact, "domain")?;
    let canonical = jcs(artifact.get("message").ok_or("missing artifact message")?)?;
    let signed = [domain.as_bytes(), canonical.as_bytes()].concat();
    let signature_object = object(artifact, "signature")?;
    let encoded = map_text(signature_object, "value")?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&signature_bytes) == encoded && signature_bytes.len() == 64,
        "invalid signature representation",
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
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| e.to_string())?;
    key.verify_strict(&signed, &signature)
        .map_err(|e| format!("{artifact_name}: {e}"))
}
fn proof_matches(
    response: &Value,
    artifact: &Value,
    enrollment: &Value,
    label: &str,
) -> Result<()> {
    let proof = object(response, "proof")?;
    let signature = object(artifact, "signature")?;
    let kid = text(enrollment, "invitationKid")?;
    assert_ok(
        map_text(signature, "alg")? == "EdDSA"
            && map_text(proof, "alg")? == "EdDSA"
            && map_text(signature, "kid")? == kid
            && map_text(proof, "kid")? == kid
            && text(artifact, "signerDid")? == text(enrollment, "nodeAudience")?
            && map_text(proof, "signature")? == map_text(signature, "value")?,
        label,
    )
}
fn validate_sd_jwt(scenario: &Value) -> Result<()> {
    let credential = object(scenario, "credential")?;
    let claims = map_object(credential, "claims")?;
    assert_ok(map_text(claims, "_sd_alg")? == "sha-256", "SD-JWT _sd_alg")?;
    let sd = map_array(claims, "_sd")?;
    assert_ok(sd.len() == 1, "SD-JWT _sd cardinality")?;
    let disclosure = map_array(credential, "disclosures")?;
    assert_ok(disclosure.len() == 1, "SD-JWT disclosure cardinality")?;
    let disclosure = &disclosure[0];
    let salt = text(disclosure, "salt")?;
    let encoded = text(disclosure, "encoded")?;
    let encoded_bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| e.to_string())?;
    assert_ok(
        URL_SAFE_NO_PAD.encode(&encoded_bytes) == encoded,
        "SD-JWT disclosure encoding",
    )?;
    let decoded: Value = serde_json::from_slice(&encoded_bytes).map_err(|e| e.to_string())?;
    let values = decoded.as_array().ok_or("SD-JWT disclosure array")?;
    assert_ok(values.len() == 3, "SD-JWT disclosure shape")?;
    assert_ok(
        values[0].as_str() == Some(salt)
            && values[1].as_str() == Some("email")
            && values[2].as_str() == Some(text(scenario, "canonicalEmail")?),
        "SD-JWT email disclosure",
    )?;
    assert_ok(
        digest(encoded.as_bytes()) == text(disclosure, "digest")?
            && sd[0].as_str() == Some(text(disclosure, "digest")?),
        "SD-JWT disclosure digest",
    )?;
    assert_ok(
        salt == text(scenario, "sdJwtSalt")?,
        "SD-JWT deterministic salt",
    )?;
    let credential_text = map_text(credential, "credential")?;
    let parts: Vec<&str> = credential_text.split('~').collect();
    assert_ok(
        parts.len() == 3 && parts[1] == encoded && parts[2].is_empty(),
        "SD-JWT compact form",
    )?;
    let jwt_parts: Vec<&str> = parts[0].split('.').collect();
    assert_ok(jwt_parts.len() == 3, "SD-JWT JWT segments")?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[0])
        .map_err(|e| e.to_string())?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    let header_object = header.as_object().ok_or("SD-JWT header object")?;
    assert_ok(
        header_object.len() == 1
            && header_object.get("alg").and_then(Value::as_str) == Some("EdDSA"),
        "SD-JWT issuer header",
    )?;
    let issuer_jws = map_object(credential, "issuerJws")?;
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    assert_ok(
        signing_input == map_text(issuer_jws, "signingInput")?
            && digest(signing_input.as_bytes()) == map_text(issuer_jws, "signingInputDigest")?
            && digest(credential_text.as_bytes()) == map_text(credential, "credentialDigest")?,
        "SD-JWT issuer preimages",
    )?;
    Ok(())
}
fn validate_negative(negative: &Value) -> Result<()> {
    let rows = array(negative, "cases")?;
    let known = [
        "email",
        "cid",
        "policy",
        "aead",
        "schema",
        "envelope",
        "signature",
        "jcs",
        "encoding",
        "did-key",
        "source",
        "binding",
        "credential",
        "state",
        "capability",
        "preimage",
        "method",
        "proof",
        "sd-jwt",
    ];
    let mut ids = Vec::new();
    for row in rows {
        let id = text(row, "id")?;
        assert_ok(
            !ids.iter().any(|seen| seen == id),
            "negative IDs must be unique",
        )?;
        ids.push(id.to_string());
        assert_ok(
            text(row, "expected")? == "reject",
            "negative expected result",
        )?;
        let kind = text(row, "kind")?;
        assert_ok(known.contains(&kind), "unknown negative kind")?;
        assert_ok(
            !text(row, "target")?.is_empty() && !text(row, "mutation")?.is_empty(),
            "negative target/mutation",
        )?;
        let mutation = object(row, "mutationData")?;
        assert_ok(
            mutation.get("operation").and_then(Value::as_str).is_some(),
            "negative mutation operation",
        )?;
        let applies = array(row, "appliesTo")?;
        assert_ok(
            !applies.is_empty()
                && applies
                    .iter()
                    .all(|value| matches!(value.as_str(), Some("kv") | Some("sql"))),
            "negative applicability",
        )?;
        if kind == "email" {
            assert_ok(text(row, "input").is_ok(), "email negative input")?;
        }
        if kind == "method" {
            assert_ok(
                mutation.get("method").and_then(Value::as_str).is_some()
                    && mutation.get("field").and_then(Value::as_str).is_some()
                    && mutation.get("value").and_then(Value::as_str).is_some(),
                "method negative mutation",
            )?;
        }
        if kind == "jcs" && id.starts_with("jcs-") {
            assert_ok(
                mutation
                    .get("jsonLiteral")
                    .and_then(Value::as_str)
                    .is_some(),
                "number negative literal",
            )?;
        }
        match id {
            "jcs-fractional-number" => assert_ok(
                mutation.get("numberKind").and_then(Value::as_str) == Some("fractional")
                    && mutation.get("jsonLiteral").and_then(Value::as_str) == Some("1.5"),
                "fractional negative",
            )?,
            "jcs-negative-zero" => assert_ok(
                mutation.get("numberKind").and_then(Value::as_str) == Some("negative-zero")
                    && mutation.get("jsonLiteral").and_then(Value::as_str) == Some("-0"),
                "negative-zero negative",
            )?,
            "jcs-unsafe-number" => assert_ok(
                mutation.get("numberKind").and_then(Value::as_str) == Some("unsafe-integer")
                    && mutation.get("jsonLiteral").and_then(Value::as_str)
                        == Some("9007199254740992"),
                "unsafe integer negative",
            )?,
            "claim-redeem-magic-with-otp" => assert_ok(
                mutation.get("method").and_then(Value::as_str) == Some("magic")
                    && mutation.get("value").and_then(Value::as_str) == Some("042731"),
                "magic/otp negative",
            )?,
            "claim-redeem-otp-with-magic" => assert_ok(
                mutation.get("method").and_then(Value::as_str) == Some("otp")
                    && mutation.get("value").and_then(Value::as_str)
                        == Some("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"),
                "otp/magic negative",
            )?,
            "sd-jwt-missing-alg" => assert_ok(
                kind == "sd-jwt"
                    && mutation.get("operation").and_then(Value::as_str) == Some("delete")
                    && mutation.get("expected").and_then(Value::as_str) == Some("sha-256"),
                "SD-JWT algorithm negative",
            )?,
            "sd-jwt-two-element-disclosure" => assert_ok(
                kind == "sd-jwt"
                    && mutation
                        .get("arrayShape")
                        .and_then(Value::as_array)
                        .is_some_and(|values| values.len() == 2),
                "SD-JWT disclosure shape negative",
            )?,
            "policy-challenge-response-proof" | "policy-session-response-proof" => {
                assert_ok(kind == "proof", "proof negative dispatch")?
            }
            _ => {}
        }
    }
    assert_ok(rows.len() >= 27, "negative matrix too small")
}
fn artifact_message<'a>(scenario: &'a Value, name: &str) -> Result<&'a Value> {
    array(scenario, "artifacts")?
        .iter()
        .find(|artifact| text(artifact, "name").ok() == Some(name))
        .and_then(|artifact| artifact.get("message"))
        .ok_or_else(|| format!("missing artifact message {name}"))
}
fn check_scope(value: &Value, expected: &Map<String, Value>, source: &Value) -> Result<()> {
    for (field, wanted) in expected {
        if let Some(actual) = value.get(field) {
            assert_ok(actual == wanted, &format!("{field} equation"))?;
        }
    }
    if let Some(actual) = value.get("contentSource") {
        assert_ok(jcs(actual)? == jcs(source)?, "content source equation")?;
    }
    Ok(())
}
fn validate_cross_equations(scenario: &Value) -> Result<()> {
    let policy = scenario.get("policy").ok_or("policy")?;
    let authorization = scenario.get("authorization").ok_or("authorization")?;
    let binding = artifact_message(scenario, "holderBinding")?;
    let canonical = text(scenario, "canonicalEmail")?;
    assert_ok(
        text(policy, "recipientEmail")? == text(authorization, "recipientEmail")?
            && text(authorization, "recipientEmail")? == canonical,
        "canonical email equation",
    )?;
    let credential = scenario.get("credential").ok_or("credential")?;
    let disclosure = array(credential, "disclosures")?
        .first()
        .ok_or("disclosure")?;
    assert_ok(
        text(disclosure, "path")? == "/email" && text(disclosure, "value")? == canonical,
        "disclosed email equation",
    )?;
    let preimages = object(scenario, "preimages")?;
    for name in ["claimRedeemRequest", "claimRedeemOtpRequest"] {
        let body = object(preimages.get(name).ok_or("redeem preimage")?, "body")?;
        assert_ok(
            map_text(body, "redemptionId")? == text(binding, "redemptionId")?
                && map_text(body, "invitationId")? == text(binding, "invitationId")?,
            "redeem identifier equation",
        )?;
    }
    let source = scenario.get("source").ok_or("source")?;
    let mut expected = Map::new();
    for field in ["shareCid", "shareId", "policyCid"] {
        expected.insert(field.into(), text(scenario, field)?.into());
    }
    expected.insert(
        "targetOrigin".into(),
        text(authorization, "targetOrigin")?.into(),
    );
    expected.insert(
        "nodeAudience".into(),
        text(authorization, "nodeAudience")?.into(),
    );
    expected.insert("holderDid".into(), text(binding, "holderDid")?.into());
    expected.insert(
        "contentSourceDigest".into(),
        text(scenario, "sourceDigest")?.into(),
    );
    expected.insert("action".into(), text(source, "action")?.into());
    expected.insert("resource".into(), text(source, "path")?.into());
    for artifact in array(scenario, "artifacts")? {
        check_scope(
            artifact.get("message").ok_or("artifact message")?,
            &expected,
            source,
        )?;
    }
    let envelope = scenario.get("envelope").ok_or("envelope")?;
    assert_ok(
        text(envelope, "shareId")? == text(scenario, "shareId")?,
        "envelope share ID equation",
    )?;
    let target = object(envelope, "target")?;
    assert_ok(
        map_text(object(envelope, "authorizationTarget")?, "policyCid")?
            == text(scenario, "policyCid")?
            && map_text(target, "origin")? == expected["targetOrigin"].as_str().unwrap_or("")
            && map_text(target, "nodeAudience")? == expected["nodeAudience"].as_str().unwrap_or("")
            && map_text(map_object(target, "resource")?, "path")?
                == expected["resource"].as_str().unwrap_or(""),
        "envelope scope equation",
    )?;
    let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
    assert_ok(
        text(enrollment, "targetOrigin")? == expected["targetOrigin"]
            && text(enrollment, "nodeAudience")? == expected["nodeAudience"],
        "enrollment equation",
    )?;
    for preimage in preimages.values() {
        let body = preimage.get("body").ok_or("preimage body")?;
        check_scope(body, &expected, source)?;
        for nested in [
            "authorization",
            "binding",
            "challenge",
            "presentation",
            "session",
            "invocation",
        ] {
            if let Some(value) = body.get(nested) {
                check_scope(value, &expected, source)?;
            }
        }
    }
    let claims = object(credential, "claims")?;
    let share = map_object(claims, "tinycloud_share")?;
    assert_ok(
        map_text(share, "share_cid")? == text(scenario, "shareCid")?
            && map_text(share, "share_id")? == text(scenario, "shareId")?
            && map_text(share, "policy_cid")? == text(scenario, "policyCid")?
            && map_text(share, "node_audience")? == expected["nodeAudience"].as_str().unwrap_or(""),
        "credential scope equation",
    )?;
    Ok(())
}
fn strict_email(input: &str) -> bool {
    if !input.is_ascii()
        || input.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        || input.matches('@').count() != 1
    {
        return false;
    }
    let (local, domain) = input.split_once('@').unwrap_or(("", ""));
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || input.len() > 254
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
    {
        return false;
    }
    let atext = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte);
    if !local
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(atext))
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}
fn artifact_message_mut<'a>(
    scenario: &'a mut Value,
    name: &str,
) -> Result<&'a mut Map<String, Value>> {
    scenario
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .and_then(|artifacts| {
            artifacts
                .iter_mut()
                .find(|artifact| text(artifact, "name").ok() == Some(name))
        })
        .and_then(|artifact| artifact.get_mut("message"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutable artifact message {name}"))
}
fn artifact_mut<'a>(scenario: &'a mut Value, name: &str) -> Result<&'a mut Map<String, Value>> {
    scenario
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .and_then(|artifacts| {
            artifacts
                .iter_mut()
                .find(|artifact| text(artifact, "name").ok() == Some(name))
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutable artifact {name}"))
}
fn preimage_body_mut<'a>(
    scenario: &'a mut Value,
    name: &str,
) -> Result<&'a mut Map<String, Value>> {
    scenario
        .get_mut("preimages")
        .and_then(Value::as_object_mut)
        .and_then(|preimages| preimages.get_mut(name))
        .and_then(|preimage| preimage.get_mut("body"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutable preimage body {name}"))
}
fn mutation_value<'a>(mutation: &'a Map<String, Value>, kind: &str) -> Option<&'a Value> {
    mutation
        .get("valueByKind")
        .and_then(|values| values.get(kind))
        .or_else(|| mutation.get("value"))
}
fn known_native_id(id: &str) -> bool {
    matches!(
        id,
        "leading-space"
            | "trailing-space"
            | "tab"
            | "newline"
            | "inner-space"
            | "leading-dot-local"
            | "trailing-dot-local"
            | "repeated-dot-local"
            | "empty-local"
            | "empty-domain"
            | "multiple-at"
            | "quoted-local"
            | "comment-local"
            | "backslash-local"
            | "angle-form"
            | "unicode-local"
            | "unicode-domain"
            | "local-over-64"
            | "label-over-63"
            | "empty-domain-label"
            | "trailing-domain-dot"
            | "leading-hyphen"
            | "trailing-hyphen"
            | "domain-over-253"
            | "total-over-254"
            | "policy-cid-is-real"
            | "policy-bytes-self-policy-cid"
            | "share-cid-is-real"
            | "sealed-blob-aead-tamper"
            | "envelope-policy-target-missing-kind"
            | "envelope-policy-target-missing-bytes"
            | "envelope-policy-target-mismatch"
            | "envelope-origin-mismatch"
            | "authorization-recipient-email-mismatch"
            | "redeem-redemption-id-mismatch"
            | "redeem-invitation-id-mismatch"
            | "share-id-propagation"
            | "share-cid-propagation"
            | "policy-cid-propagation"
            | "target-origin-propagation"
            | "node-audience-propagation"
            | "holder-did-propagation"
            | "content-source-digest-propagation"
            | "action-propagation"
            | "resource-propagation"
            | "envelope-domain-from-unregistered-label"
            | "jcs-lone-surrogate"
            | "jcs-unsafe-number"
            | "jcs-fractional-number"
            | "jcs-negative-zero"
            | "jcs-undefined"
            | "noncanonical-b64url-16-tail"
            | "noncanonical-b64url-64-tail"
            | "noncanonical-holder-kid"
            | "small-order-did-key"
            | "noncanonical-ed25519-s"
            | "short-signature"
            | "wrong-source-digest"
            | "sql-arguments-too-large"
            | "sql-arbitrary-query-field"
            | "policy-action-source-mismatch"
            | "content-source-propagation"
            | "credential-sub-mismatch"
            | "credential-legacy-email-path"
            | "credential-unsupported-status"
            | "different-holder-valid-signature"
            | "policy-challenge-replay"
            | "session-token-only"
            | "old-secret-after-resend"
            | "otp-after-five-wrong"
            | "scanner-get"
            | "resend-recipient-supplied-email"
            | "capability-extra-route"
            | "capability-wildcard-origin"
            | "read-body-one-field-mutation"
            | "claim-redeem-magic-with-otp"
            | "claim-redeem-otp-with-magic"
            | "policy-challenge-response-proof"
            | "policy-session-response-proof"
            | "sd-jwt-missing-alg"
            | "sd-jwt-two-element-disclosure"
    )
}
fn apply_negative_mutation(
    scenario: &mut Value,
    states: &mut Value,
    row: &Value,
    kind: &str,
) -> Result<()> {
    let target = text(row, "target")?;
    let mutation = object(row, "mutationData")?;
    let value = mutation_value(mutation, kind).cloned();
    match target {
        "canonicalEmail" => {
            scenario["canonicalEmail"] = Value::String(map_text(mutation, "input")?.into());
        }
        "policyBytes" => match mutation.get("operation").and_then(Value::as_str) {
            Some("replace") => {
                let replacement = map_text(mutation, "replacement")?;
                scenario["policyBytes"] = Value::String(URL_SAFE_NO_PAD.encode(replacement));
            }
            Some("insert-property") => {
                let mut policy = object(scenario, "policy")?.clone();
                policy.insert(
                    map_text(mutation, "property")?.into(),
                    mutation
                        .get("value")
                        .cloned()
                        .ok_or("policy property value")?,
                );
                let bytes = jcs(&Value::Object(policy))?.into_bytes();
                scenario["policyBytes"] = Value::String(URL_SAFE_NO_PAD.encode(bytes));
            }
            _ => return Err(format!("unsupported policyBytes mutation {target}")),
        },
        "sealedBlob" => {
            let mut blob = b64(scenario, "sealedBlob")?;
            let last = blob.last_mut().ok_or("empty sealed blob")?;
            *last ^= 1;
            scenario["sealedBlob"] = Value::String(URL_SAFE_NO_PAD.encode(blob));
        }
        "envelope.authorizationTarget.kind" | "envelope.authorizationTarget.policyBytes" => {
            let target = scenario
                .get_mut("envelope")
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("authorizationTarget"))
                .and_then(Value::as_object_mut)
                .ok_or("authorization target")?;
            let field = text(row, "target")?
                .rsplit('.')
                .next()
                .ok_or("authorization target field")?;
            target.remove(field);
        }
        "envelope.authorizationTarget" => {
            let target = scenario
                .get_mut("envelope")
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("authorizationTarget"))
                .and_then(Value::as_object_mut)
                .ok_or("authorization target")?;
            target.insert("kind".into(), Value::String("policy".into()));
            target.insert("policyCid".into(), map_text(mutation, "policyCid")?.into());
            target.insert(
                "policyBytes".into(),
                map_text(mutation, "policyBytes")?.into(),
            );
        }
        "envelope.target.origin" => {
            let target = scenario
                .get_mut("envelope")
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("target"))
                .and_then(Value::as_object_mut)
                .ok_or("envelope target")?;
            target.insert("origin".into(), value.ok_or("envelope origin")?);
        }
        "inviteAuthorization.recipientEmail" => {
            artifact_message_mut(scenario, "inviteAuthorization")?
                .insert("recipientEmail".into(), value.ok_or("recipient email")?);
        }
        "holderBinding.redemptionId" | "holderBinding.invitationId" => {
            let field = target.rsplit('.').next().ok_or("binding field")?;
            artifact_message_mut(scenario, "holderBinding")?
                .insert(field.into(), value.ok_or("binding value")?);
        }
        "policyPresentation.contentSource.path" => {
            let mut source = object(scenario, "source")?.clone();
            source.insert("path".into(), value.ok_or("content source path")?);
            artifact_message_mut(scenario, "policyPresentation")?
                .insert("contentSource".into(), Value::Object(source));
        }
        "policyPresentation.shareId"
        | "policyPresentation.shareCid"
        | "policyPresentation.policyCid"
        | "policyPresentation.targetOrigin"
        | "policyPresentation.nodeAudience"
        | "policyPresentation.holderDid"
        | "policyPresentation.contentSourceDigest"
        | "policyPresentation.action"
        | "policyPresentation.resource" => {
            let field = target.rsplit('.').next().ok_or("presentation field")?;
            artifact_message_mut(scenario, "policyPresentation")?
                .insert(field.into(), value.ok_or("presentation value")?);
        }
        "envelope.domain" => {
            artifact_mut(scenario, "envelope")?
                .insert("domain".into(), value.ok_or("envelope domain")?);
        }
        "value" => {
            scenario["nativeMutation"] = Value::Object(
                [(
                    "jsonLiteral".into(),
                    Value::String(map_text(mutation, "jsonLiteral")?.into()),
                )]
                .into_iter()
                .collect(),
            );
        }
        "invitationId" => {
            preimage_body_mut(scenario, "claimRedeemRequest")?
                .insert("invitationId".into(), value.ok_or("invitation ID")?);
        }
        "signature" => {
            artifact_mut(scenario, "readInvocation")?
                .get_mut("signature")
                .and_then(Value::as_object_mut)
                .ok_or("read signature")?
                .insert("value".into(), value.ok_or("signature value")?);
        }
        "holderBinding.signature.kid" => {
            preimage_body_mut(scenario, "claimRedeemRequest")?
                .get_mut("holderProof")
                .and_then(Value::as_object_mut)
                .ok_or("holder proof")?
                .insert("kid".into(), value.ok_or("holder kid")?);
        }
        "holderBinding.signature.value" => {
            artifact_mut(scenario, "holderBinding")?
                .get_mut("signature")
                .and_then(Value::as_object_mut)
                .ok_or("holder signature")?
                .insert("value".into(), value.ok_or("holder signature value")?);
        }
        "holderBinding.holderDid" => {
            artifact_message_mut(scenario, "holderBinding")?
                .insert("holderDid".into(), value.ok_or("holder DID")?);
        }
        "readInvocation.signature.value" => {
            let signature = artifact_mut(scenario, "readInvocation")?
                .get_mut("signature")
                .and_then(Value::as_object_mut)
                .ok_or("read signature")?;
            let bytes = mutation
                .get("bytes")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .ok_or("signature byte count")?;
            let original = b64_map(signature, "value")?;
            assert_ok(bytes < original.len(), "signature truncation length")?;
            signature.insert(
                "value".into(),
                Value::String(URL_SAFE_NO_PAD.encode(&original[..bytes])),
            );
        }
        "sql.argumentsDigest" | "sql.arguments" => {
            let source = scenario
                .get_mut("source")
                .and_then(Value::as_object_mut)
                .ok_or("source")?;
            let arguments = source
                .get_mut("arguments")
                .and_then(Value::as_object_mut)
                .ok_or("SQL arguments")?;
            if target == "sql.argumentsDigest" {
                arguments.insert(
                    map_text(mutation, "field")?
                        .rsplit('.')
                        .next()
                        .unwrap_or("field")
                        .into(),
                    value.ok_or("SQL argument")?,
                );
            } else {
                arguments.insert(
                    map_text(mutation, "field")?.into(),
                    value.ok_or("SQL argument")?,
                );
            }
        }
        "sqlSource.query" => {
            scenario
                .get_mut("source")
                .and_then(Value::as_object_mut)
                .ok_or("source")?
                .insert(map_text(mutation, "field")?.into(), value.ok_or("query")?);
        }
        "policy.action" => {
            scenario
                .get_mut("policy")
                .and_then(Value::as_object_mut)
                .ok_or("policy")?
                .insert("action".into(), value.ok_or("policy action")?);
        }
        "credential.claims.sub" | "credential.claims.status" => {
            let claims = scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("claims"))
                .and_then(Value::as_object_mut)
                .ok_or("credential claims")?;
            let field = target.rsplit('.').next().ok_or("credential field")?;
            if mutation.get("operation").and_then(Value::as_str) == Some("delete") {
                claims.remove(field);
            } else {
                claims.insert(field.into(), value.ok_or("credential value")?);
            }
        }
        "credential.disclosures[0].path" => {
            let disclosure = scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("disclosures"))
                .and_then(Value::as_array_mut)
                .and_then(|disclosures| disclosures.first_mut())
                .and_then(Value::as_object_mut)
                .ok_or("credential disclosure")?;
            disclosure.insert("path".into(), value.ok_or("disclosure path")?);
        }
        "nonce.state" | "invitation.version" | "otp.attempts" => match target {
            "nonce.state" => states["nonceTransition"] = Value::Object(mutation.clone()),
            "invitation.version" => {
                states["invitationVersion"] =
                    mutation.get("value").cloned().ok_or("invitation version")?
            }
            "otp.attempts" => {
                states["otpAttempts"] = mutation.get("value").cloned().ok_or("OTP attempts")?
            }
            _ => return Err("unknown state mutation".into()),
        },
        "read.proof" => {
            let name = if kind == "sql" {
                "sqlReadRequest"
            } else {
                "kvReadRequest"
            };
            preimage_body_mut(scenario, name)?.remove("proof");
        }
        "fragment" | "resendRequest.email" => {
            if target == "fragment" {
                scenario["fragment"] = value.ok_or("fragment")?;
            } else {
                preimage_body_mut(scenario, "resendRequest")?
                    .insert("email".into(), value.ok_or("resend email")?);
            }
        }
        "witness.routes" => {
            let action = map_text(object(scenario, "source")?, "action")?;
            let route = format!(
                "/v1/{}",
                action.strip_prefix("tinycloud.").unwrap_or(action)
            );
            scenario["nativeCapability"] = Value::Object(
                [(
                    "routes".into(),
                    Value::Array(vec![Value::String(route), value.ok_or("capability route")?]),
                )]
                .into_iter()
                .collect(),
            );
        }
        "node.origin" => {
            scenario["nativeCapability"] = Value::Object(
                [(
                    "origin".into(),
                    Value::String(
                        value
                            .ok_or("capability origin")?
                            .as_str()
                            .ok_or("origin")?
                            .into(),
                    ),
                )]
                .into_iter()
                .collect(),
            );
        }
        "sqlReadRequest.resource" => {
            preimage_body_mut(scenario, "sqlReadRequest")?
                .insert("resource".into(), value.ok_or("read resource")?);
        }
        "claimRedeemRequest.mailboxProof" => {
            let name = if map_text(mutation, "method")? == "otp" {
                "claimRedeemOtpRequest"
            } else {
                "claimRedeemRequest"
            };
            preimage_body_mut(scenario, name)?
                .insert("mailboxProof".into(), value.ok_or("mailbox proof")?);
        }
        "policyChallengeResponse.proof" | "policySessionResponse.proof" => {
            let response_name = if target.starts_with("policyChallenge") {
                "policyChallengeResponse"
            } else {
                "policySessionResponse"
            };
            let artifact_name = map_text(mutation, "artifact")?;
            let signature = object(
                array(scenario, "artifacts")?
                    .iter()
                    .find(|artifact| text(artifact, "name").ok() == Some(artifact_name))
                    .ok_or("proof artifact")?,
                "signature",
            )?;
            let proof = Value::Object(
                [
                    ("alg".into(), Value::String("EdDSA".into())),
                    ("kid".into(), map_text(mutation, "signer")?.into()),
                    ("signature".into(), map_text(signature, "value")?.into()),
                ]
                .into_iter()
                .collect(),
            );
            preimage_body_mut(scenario, response_name)?.insert("proof".into(), proof);
        }
        "credential.claims._sd_alg" => {
            scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("claims"))
                .and_then(Value::as_object_mut)
                .ok_or("credential claims")?
                .remove("_sd_alg");
        }
        "credential.disclosures[0].encoded" => {
            let shape = mutation
                .get("arrayShape")
                .and_then(Value::as_array)
                .ok_or("disclosure shape")?;
            let encoded =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(shape).map_err(|e| e.to_string())?);
            scenario
                .get_mut("credential")
                .and_then(Value::as_object_mut)
                .and_then(|credential| credential.get_mut("disclosures"))
                .and_then(Value::as_array_mut)
                .and_then(|disclosures| disclosures.first_mut())
                .and_then(Value::as_object_mut)
                .ok_or("credential disclosure")?
                .insert("encoded".into(), encoded.into());
        }
        _ => return Err(format!("unknown native negative target {target}")),
    }
    Ok(())
}
fn validate_mutated_candidate(
    scenario: &Value,
    states: &Value,
    row: &Value,
    kind: &str,
    domains: &Map<String, Value>,
) -> Result<()> {
    let target = text(row, "target")?;
    let mutation = object(row, "mutationData")?;
    match target {
        "canonicalEmail" => assert_ok(
            strict_email(text(scenario, "canonicalEmail")?),
            "invalid email accepted",
        ),
        "policyBytes" => {
            let bytes = b64(scenario, "policyBytes")?;
            assert_ok(
                cid(&bytes) == text(scenario, "policyCid")?,
                "policy bytes CID mismatch",
            )
        }
        "sealedBlob" => {
            let blob = b64(scenario, "sealedBlob")?;
            assert_ok(
                cid(&blob) == text(scenario, "shareCid")?,
                "sealed blob CID mismatch",
            )
        }
        "envelope.authorizationTarget.kind" | "envelope.authorizationTarget.policyBytes" => {
            let target = object(
                scenario.get("envelope").ok_or("envelope")?,
                "authorizationTarget",
            )?;
            assert_ok(target.contains_key("kind"), "envelope kind missing")?;
            assert_ok(
                target.contains_key("policyBytes"),
                "envelope policy bytes missing",
            )
        }
        "envelope.authorizationTarget" => {
            let target = object(
                scenario.get("envelope").ok_or("envelope")?,
                "authorizationTarget",
            )?;
            let bytes = b64(&Value::Object(target.clone()), "policyBytes")?;
            assert_ok(
                map_text(target, "kind")? == "policy"
                    && map_text(target, "policyCid")? == text(scenario, "policyCid")?
                    && cid(&bytes) == text(scenario, "policyCid")?,
                "envelope policy target mismatch",
            )
        }
        "envelope.target.origin" => assert_ok(
            map_text(
                object(scenario.get("envelope").ok_or("envelope")?, "target")?,
                "origin",
            )? == text(
                scenario.get("enrollment").ok_or("enrollment")?,
                "targetOrigin",
            )?,
            "envelope origin mismatch",
        ),
        "inviteAuthorization.recipientEmail" => assert_ok(
            text(
                artifact_message(scenario, "inviteAuthorization")?,
                "recipientEmail",
            )? == text(scenario, "canonicalEmail")?,
            "authorization recipient mismatch",
        ),
        "holderBinding.redemptionId" | "holderBinding.invitationId" => {
            let field = target.rsplit('.').next().ok_or("binding field")?;
            let binding = artifact_message(scenario, "holderBinding")?;
            let body = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "claimRedeemRequest",
                )?,
                "body",
            )?;
            assert_ok(
                text(binding, field)? == map_text(body, field)?,
                "binding ID mismatch",
            )
        }
        "policyPresentation.contentSource.path"
        | "policyPresentation.shareId"
        | "policyPresentation.shareCid"
        | "policyPresentation.policyCid"
        | "policyPresentation.targetOrigin"
        | "policyPresentation.nodeAudience"
        | "policyPresentation.holderDid"
        | "policyPresentation.contentSourceDigest"
        | "policyPresentation.action"
        | "policyPresentation.resource" => validate_cross_equations(scenario),
        "policy.action" => assert_ok(
            map_text(object(scenario, "policy")?, "action")?
                == map_text(object(scenario, "source")?, "action")?,
            "policy action/source mismatch",
        ),
        "envelope.domain" => {
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("envelope"))
                .ok_or("envelope artifact")?;
            let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
            verify_artifact(artifact, "envelope", domains, enrollment)
        }
        "value" => {
            let literal = map_text(object(scenario, "nativeMutation")?, "jsonLiteral")?;
            let parsed: Value = serde_json::from_str(literal).map_err(|e| e.to_string())?;
            jcs(&parsed).map(|_| ())
        }
        "invitationId" => b64_map(
            map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "claimRedeemRequest",
                )?,
                "body",
            )?,
            "invitationId",
        )
        .map(|_| ())
        .map_err(|e| e.to_string()),
        "signature" | "readInvocation.signature.value" => {
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("readInvocation"))
                .ok_or("read artifact")?;
            let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
            verify_signature_core(artifact, "readInvocation", enrollment)?;
            verify_artifact(artifact, "readInvocation", domains, enrollment)
        }
        "holderBinding.signature.kid" => {
            let binding = artifact_message(scenario, "holderBinding")?;
            let holder = text(binding, "holderDid")?;
            let expected = format!(
                "{}#{}",
                holder,
                holder.strip_prefix("did:key:z").unwrap_or(holder)
            );
            let body = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "claimRedeemRequest",
                )?,
                "body",
            )?;
            let proof = map_object(body, "holderProof")?;
            assert_ok(map_text(proof, "kid")? == expected, "holder kid mismatch")
        }
        "holderBinding.signature.value" | "holderBinding.holderDid" => {
            let holder = text(artifact_message(scenario, "holderBinding")?, "holderDid")?;
            let raw = did_key_bytes(holder)?;
            let key = VerifyingKey::from_bytes(&raw).map_err(|e| e.to_string())?;
            assert_ok(!key.is_weak(), "weak holder key")?;
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("holderBinding"))
                .ok_or("holder artifact")?;
            let enrollment = scenario.get("enrollment").ok_or("enrollment")?;
            verify_signature_core(artifact, "holderBinding", enrollment)?;
            verify_artifact(artifact, "holderBinding", domains, enrollment)
        }
        "sql.argumentsDigest" | "sql.arguments" => {
            let source = scenario.get("source").ok_or("source")?;
            let arguments = object(source, "arguments")?;
            let canonical = jcs(&Value::Object(arguments.clone()))?;
            assert_ok(
                digest(canonical.as_bytes()) == text(source, "argumentsDigest")?,
                "SQL arguments digest mismatch",
            )
        }
        "sqlSource.query" => assert_ok(
            !object(scenario, "source")?.contains_key("query"),
            "arbitrary SQL query field accepted",
        ),
        "credential.claims.sub" => {
            let credential = object(scenario, "credential")?;
            assert_ok(
                map_text(map_object(credential, "claims")?, "sub")?
                    == map_text(credential, "holderDid")?,
                "credential subject mismatch",
            )
        }
        "credential.disclosures[0].path" => {
            let disclosure = map_array(object(scenario, "credential")?, "disclosures")?
                .first()
                .ok_or("disclosure")?;
            assert_ok(
                text(disclosure, "path")? == "/email",
                "legacy disclosure path",
            )
        }
        "credential.claims.status" => assert_ok(
            !map_object(object(scenario, "credential")?, "claims")?.contains_key("status"),
            "unsupported credential status",
        ),
        "nonce.state" => {
            let changed = object(states, "nonceTransition")?;
            assert_ok(
                map_text(changed, "from")? != map_text(changed, "to")?
                    && map_text(changed, "from")? != "CONSUMED",
                "invalid nonce transition accepted",
            )
        }
        "read.proof" => {
            let name = if kind == "sql" {
                "sqlReadRequest"
            } else {
                "kvReadRequest"
            };
            let body = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, name)?,
                "body",
            )?;
            map_object(body, "proof").map(|_| ())
        }
        "invitation.version" => {
            let version = states
                .get("invitationVersion")
                .and_then(Value::as_i64)
                .ok_or("invitation version")?;
            let operations = array(states, "operations")?;
            assert_ok(
                !(version == 1
                    && operations
                        .iter()
                        .any(|op| op.as_str() == Some("invalidate_v1"))),
                "old invitation version accepted after resend",
            )
        }
        "otp.attempts" => {
            let attempts = states
                .get("otpAttempts")
                .and_then(Value::as_i64)
                .ok_or("OTP attempts")?;
            let threshold = map_object(object(states, "semantics")?, "otp")?
                .get("wrongAttemptsBeforeLock")
                .and_then(Value::as_i64)
                .ok_or("OTP threshold")?;
            assert_ok(
                !(attempts >= threshold
                    && map_text(
                        map_object(object(states, "semantics")?, "otp")?,
                        "correctAfterLock",
                    )? == "reject"),
                "locked OTP accepted",
            )
        }
        "fragment" => {
            let url = text(scenario, "fragment")?;
            assert_ok(
                !url.split_once('#')
                    .is_some_and(|(_, fragment)| !fragment.is_empty()),
                "GET consumed claim",
            )
        }
        "resendRequest.email" => assert_ok(
            !map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "resendRequest",
                )?,
                "body",
            )?
            .contains_key("email"),
            "recipient email accepted by resend",
        ),
        "witness.routes" => {
            let capability = object(scenario, "nativeCapability")?;
            let routes = map_array(capability, "routes")?;
            let action = text(scenario.get("source").ok_or("source")?, "action")?;
            let expected = format!(
                "/v1/{}",
                action.strip_prefix("tinycloud.").unwrap_or(action)
            );
            assert_ok(
                routes.len() == 1
                    && routes
                        .iter()
                        .all(|route| route.as_str() == Some(expected.as_str())),
                "capability route outside allowlist",
            )
        }
        "node.origin" => {
            let capability = object(scenario, "nativeCapability")?;
            let origin = map_text(capability, "origin")?;
            assert_ok(
                !origin.contains('*')
                    && origin
                        == text(
                            scenario.get("enrollment").ok_or("enrollment")?,
                            "targetOrigin",
                        )?,
                "capability wildcard origin",
            )
        }
        "sqlReadRequest.resource" => {
            let preimage = map_object(
                object(
                    scenario.get("preimages").ok_or("preimages")?,
                    "sqlReadRequest",
                )?,
                "body",
            )?;
            let canonical = jcs(&Value::Object(preimage.clone()))?;
            assert_ok(
                digest(canonical.as_bytes())
                    == map_text(
                        object(
                            scenario.get("preimages").ok_or("preimages")?,
                            "sqlReadRequest",
                        )?,
                        "digest",
                    )?,
                "read body digest mismatch",
            )
        }
        "claimRedeemRequest.mailboxProof" => {
            let method = map_text(mutation, "method")?;
            let name = if method == "otp" {
                "claimRedeemOtpRequest"
            } else {
                "claimRedeemRequest"
            };
            let body = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, name)?,
                "body",
            )?;
            let expected_name = if method == "otp" {
                "claimChallengeOtpRequest"
            } else {
                "claimChallengeMagicRequest"
            };
            let expected_body = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, expected_name)?,
                "body",
            )?;
            assert_ok(
                map_text(body, "method")? == method
                    && map_text(body, "mailboxProof")?
                        == if method == "otp" {
                            map_text(expected_body, "otp")?
                        } else {
                            map_text(expected_body, "claimSecret")?
                        },
                "redeem method/proof mismatch",
            )
        }
        "policyChallengeResponse.proof" | "policySessionResponse.proof" => {
            let response_name = if target.starts_with("policyChallenge") {
                "policyChallengeResponse"
            } else {
                "policySessionResponse"
            };
            let artifact_name = map_text(mutation, "artifact")?;
            let artifact = array(scenario, "artifacts")?
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some(artifact_name))
                .ok_or("proof artifact")?;
            let response = map_object(
                object(scenario.get("preimages").ok_or("preimages")?, response_name)?,
                "body",
            )?;
            proof_matches(
                &Value::Object(response.clone()),
                artifact,
                scenario.get("enrollment").ok_or("enrollment")?,
                "response proof",
            )
        }
        "credential.claims._sd_alg" | "credential.disclosures[0].encoded" => {
            validate_sd_jwt(scenario)
        }
        _ => Err(format!("unknown native negative target {target}")),
    }
}
fn validate_negative_native(
    positive: &Value,
    negative: &Value,
    states: &Value,
    domains: &Map<String, Value>,
) -> Result<()> {
    let rows = array(negative, "cases")?;
    let scenarios = array(positive, "scenarios")?;
    let mut ids = Vec::new();
    for row in rows {
        let id = text(row, "id")?;
        assert_ok(
            known_native_id(id),
            &format!("unknown native negative ID {id}"),
        )?;
        assert_ok(
            !ids.iter().any(|seen| seen == id),
            "duplicate native negative ID",
        )?;
        ids.push(id.to_string());
        assert_ok(
            text(row, "expected")? == "reject",
            "negative expected marker",
        )?;
        let mutation_text = serde_json::to_string(row.get("mutationData").ok_or("mutation data")?)
            .map_err(|e| e.to_string())?;
        assert_ok(
            !mutation_text.contains("scenario."),
            "symbolic negative mutation",
        )?;
        let applies = array(row, "appliesTo")?;
        for scenario in scenarios {
            let kind = text(scenario, "kind")?;
            if !applies.iter().any(|value| value.as_str() == Some(kind)) {
                continue;
            }
            let mut candidate = scenario.clone();
            let mut state_candidate = states.clone();
            apply_negative_mutation(&mut candidate, &mut state_candidate, row, kind)?;
            if let Ok(()) =
                validate_mutated_candidate(&candidate, &state_candidate, row, kind, domains)
            {
                return Err(format!("native negative accepted: {id}/{kind}"));
            }
        }
    }
    assert_ok(ids.len() == rows.len(), "native negative coverage")?;
    validate_recovery_native(states)
}
fn validate_recovery_native(states: &Value) -> Result<()> {
    let recovery_value = states.get("issuanceRecovery").ok_or("issuanceRecovery")?;
    let recovery = recovery_value
        .as_object()
        .ok_or("issuanceRecovery object")?;
    assert_ok(
        recovery.get("seedCiphertext") == recovery.get("retrySeedCiphertext")
            && recovery.get("pendingSeedCiphertext") == recovery.get("retryPendingSeedCiphertext")
            && recovery.get("seedCiphertext") == recovery.get("pendingSeedCiphertext"),
        "retry seed bytes changed",
    )?;
    let timeline = map_array(recovery, "timeline")?;
    assert_ok(timeline.len() == 5, "recovery timeline length")?;
    assert_ok(
        text(&timeline[0], "state")? == "PENDING_ENCRYPTED"
            && text(&timeline[1], "event")? == "credential_generated_then_crash"
            && timeline[1].get("credentialGenerated") == Some(&Value::Bool(true))
            && timeline[1].get("durableCompletion") == Some(&Value::Bool(false))
            && text(&timeline[2], "event")? == "retry_same_seed"
            && timeline[3].get("durableCompletion") == Some(&Value::Bool(true))
            && timeline[3].get("durableCompletionAt")
                == Some(&Value::from("2026-07-16T12:00:03.000Z"))
            && timeline[3].get("resultPersisted") == Some(&Value::Bool(true))
            && text(&timeline[4], "state")? == "CONSUMED"
            && timeline[4].get("consumedPersisted") == Some(&Value::Bool(true))
            && timeline[4].get("resultPersisted") == Some(&Value::Bool(true))
            && timeline[4].get("atomicConsumedAndResult") == Some(&Value::Bool(true))
            && timeline[4].get("resultDigest") == recovery.get("resultDigest"),
        "recovery timeline ordering",
    )?;
    for event in &timeline[..3] {
        assert_ok(
            event.get("seedEncrypted") == Some(&Value::Bool(true)),
            "pending seed must remain encrypted",
        )?;
    }
    assert_ok(
        timeline[4].get("seedEncrypted") == Some(&Value::Bool(false)),
        "consumed seed cleanup",
    )?;
    let failure = map_array(recovery, "terminalFailureTimeline")?;
    assert_ok(
        failure.len() == 3
            && text(&failure[0], "state")? == "PENDING_ENCRYPTED"
            && failure[0].get("seedEncrypted") == Some(&Value::Bool(true))
            && text(&failure[1], "state")? == "RETRYING"
            && failure[1].get("seedEncrypted") == Some(&Value::Bool(true))
            && text(&failure[2], "state")? == "TERMINAL_ERROR"
            && failure[2].get("terminalErrorPersisted") == Some(&Value::Bool(true))
            && failure[2].get("seedEncrypted") == Some(&Value::Bool(false))
            && failure[2].get("atomicTerminalAndSeedDeletion") == Some(&Value::Bool(true))
            && text(&failure[2], "errorCode")? == "credential_issuance_failed",
        "atomic terminal failure",
    )?;
    let invariants = map_object(recovery, "invariants")?;
    for key in [
        "pendingSeedEncrypted",
        "retrySeedByteIdentical",
        "completionRequiresDurableWrite",
        "consumedAndResultPersistedAtomically",
        "terminalResolutionAtomic",
        "cleanupRefusesPendingSeed",
    ] {
        assert_ok(invariants.get(key) == Some(&Value::Bool(true)), key)?;
    }
    assert_ok(
        invariants.get("durableCompletionAt") == Some(&Value::from("2026-07-16T12:00:03.000Z"))
            && invariants.get("redactionWindowSeconds") == Some(&Value::from(900))
            && map_text(invariants, "redactionStartsOnlyAt")? == "durable_completion"
            && map_text(invariants, "redactionMeasuredFrom")? == "2026-07-16T12:00:03.000Z"
            && map_text(invariants, "redactionAt")? == "2026-07-16T12:15:03.000Z",
        "redaction window",
    )?;
    let cleanup = map_object(recovery, "cleanup")?;
    assert_ok(
        map_text(cleanup, "pendingSeedAction")? == "refuse"
            && cleanup.get("pendingSeedRemains") == Some(&Value::Bool(true))
            && map_text(cleanup, "completedSeedAction")? == "delete",
        "cleanup policy",
    )?;
    let terminal = map_object(recovery, "terminalResolution")?;
    assert_ok(
        terminal.get("atomic") == Some(&Value::Bool(true))
            && terminal.get("atomicConsumedAndResultPersisted") == Some(&Value::Bool(true))
            && terminal.get("atomicTerminalAndSeedDeletion") == Some(&Value::Bool(true))
            && map_text(terminal, "successOutcome")? == "CONSUMED"
            && map_text(terminal, "failureOutcome")? == "TERMINAL_ERROR",
        "terminal resolution",
    )?;
    assert_ok(
        digest(
            &URL_SAFE_NO_PAD
                .decode(map_text(recovery, "resultBytes")?)
                .map_err(|e| e.to_string())?,
        ) == map_text(recovery, "resultDigest")?,
        "result digest",
    )?;
    Ok(())
}
fn expect_string_array(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let values = value.as_array().ok_or_else(|| format!("{label}: array"))?;
    assert_ok(values.len() == expected.len(), label)?;
    for (actual, wanted) in values.iter().zip(expected) {
        assert_ok(actual.as_str() == Some(*wanted), label)?;
    }
    Ok(())
}
fn validate_states(states: &Value) -> Result<()> {
    let delivery = array(states, "delivery")?;
    assert_ok(delivery.len() == 4, "delivery state count")?;
    let names = [
        "create-accepted",
        "resend-accepted",
        "resend-provider-failure",
        "crash-after-provider-accept",
    ];
    for name in names {
        assert_ok(
            delivery
                .iter()
                .any(|flow| text(flow, "name").ok() == Some(name)),
            "delivery state name",
        )?;
    }
    for flow in delivery {
        let events = array(flow, "events")?;
        assert_ok(!events.is_empty(), "delivery events")?;
        let mut current = events[0]
            .as_array()
            .and_then(|event| event.first())
            .and_then(Value::as_str)
            .ok_or("delivery event source")?;
        for event in events {
            let pair = event.as_array().ok_or("delivery event pair")?;
            assert_ok(
                pair.len() == 2 && pair[0].as_str() == Some(current),
                "delivery transition source",
            )?;
            current = pair[1].as_str().ok_or("delivery transition target")?;
        }
        match text(flow, "name")? {
            "create-accepted" => assert_ok(
                flow.get("encryptedUntilProviderAcceptance") == Some(&Value::Bool(true))
                    && flow.get("atomicActivation") == Some(&Value::Bool(true))
                    && flow.get("materialDeletedAfterAccept") == Some(&Value::Bool(true)),
                "create delivery invariants",
            )?,
            "resend-accepted" => assert_ok(
                flow.get("oldVersionRemainsActiveWhilePending") == Some(&Value::Bool(true))
                    && flow.get("oldVersionInvalidatedOnlyAfterAccept") == Some(&Value::Bool(true))
                    && flow.get("replacementMaterialEncryptedUntilAcceptance")
                        == Some(&Value::Bool(true))
                    && flow.get("atomicActivation") == Some(&Value::Bool(true)),
                "resend delivery invariants",
            )?,
            "resend-provider-failure" => assert_ok(
                flow.get("oldVersionRemainsUsable") == Some(&Value::Bool(true))
                    && flow.get("replacementDiscardedOnFailure") == Some(&Value::Bool(true)),
                "failed resend invariants",
            )?,
            "crash-after-provider-accept" => assert_ok(
                flow.get("providerAcceptedBeforeCrash") == Some(&Value::Bool(true))
                    && flow.get("sameIdempotencyKeyOnRetry") == Some(&Value::Bool(true))
                    && flow.get("recoveryReconcilesProviderAcceptance") == Some(&Value::Bool(true))
                    && flow.get("oneEffectiveSend") == Some(&Value::Bool(true))
                    && flow.get("oldVersionInvalidatedAfterRecovery") == Some(&Value::Bool(true)),
                "crash recovery invariants",
            )?,
            _ => return Err("unknown delivery flow".into()),
        }
    }
    expect_string_array(
        states.get("invitation").ok_or("invitation states")?,
        &[
            "ABSENT",
            "ACTIVE(v1)",
            "REDEEMING(v1,redemption-001)",
            "CONSUMED(v1)",
        ],
        "invitation states",
    )?;
    expect_string_array(
        states.get("nonce").ok_or("nonce states")?,
        &["ISSUED", "VERIFYING", "CONSUMED"],
        "nonce states",
    )?;
    let session = array(states, "session")?;
    assert_ok(
        session
            .iter()
            .any(|value| value.as_str() == Some("EXPIRED"))
            && session
                .iter()
                .any(|value| value.as_str() == Some("REVOKED")),
        "session terminal states",
    )?;
    let semantics = object(states, "semantics")?;
    let race = map_object(semantics, "sameRedemptionConcurrency")?;
    assert_ok(
        race.get("attempts") == Some(&Value::from(20))
            && race.get("effectiveIssuances") == Some(&Value::from(1))
            && race.get("sameResultForSameId") == Some(&Value::Bool(true)),
        "redemption race invariants",
    )?;
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
    let negative = read_json(&vector_dir.join("negative.json"))?;
    let states = read_json(&vector_dir.join("states.json"))?;
    let domains_map = object(&domains, "domains")?;
    validate_negative(&negative)?;
    validate_states(&states)?;
    validate_negative_native(&positive, &negative, &states, domains_map)?;
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
        assert_ok(artifacts.len() == 8, "signed artifact count")?;
        let mut artifact_names = Vec::new();
        for artifact in artifacts {
            let name = text(artifact, "name")?;
            assert_ok(
                !artifact_names.iter().any(|seen| seen == name),
                "signed artifact IDs unique",
            )?;
            artifact_names.push(name.to_string());
            verify_artifact(artifact, name, domains_map, enrollment)?;
        }
        for required in [
            "policy",
            "envelope",
            "inviteAuthorization",
            "holderBinding",
            "policyChallenge",
            "policyPresentation",
            "policySession",
            "readInvocation",
        ] {
            assert_ok(
                artifact_names.iter().any(|name| name == required),
                "signed artifact set",
            )?;
        }
        let preimages = object(scenario, "preimages")?;
        for required in [
            "claimRedeemRequest",
            "claimRedeemOtpRequest",
            "policyChallengeResponse",
            "policySessionResponse",
            "claimChallengeResponse",
        ] {
            assert_ok(
                preimages.get(required).is_some(),
                "endpoint preimage matrix",
            )?;
        }
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
        proof_matches(
            preimages
                .get("policyChallengeResponse")
                .and_then(|preimage| preimage.get("body"))
                .ok_or("challenge response")?,
            artifacts
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("policyChallenge"))
                .ok_or("challenge artifact")?,
            enrollment,
            "challenge response proof",
        )?;
        proof_matches(
            preimages
                .get("policySessionResponse")
                .and_then(|preimage| preimage.get("body"))
                .ok_or("session response")?,
            artifacts
                .iter()
                .find(|artifact| text(artifact, "name").ok() == Some("policySession"))
                .ok_or("session artifact")?,
            enrollment,
            "session response proof",
        )?;
        validate_sd_jwt(scenario)?;
        validate_cross_equations(scenario)?;
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
