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
fn proof_matches(response: &Value, artifact: &Value, label: &str) -> Result<()> {
    let proof = object(response, "proof")?;
    let signature = object(artifact, "signature")?;
    assert_ok(
        proof.get("alg") == signature.get("alg")
            && proof.get("kid") == signature.get("kid")
            && proof.get("signature") == signature.get("value"),
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
                        == Some("scenario.claimSecret"),
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
    validate_negative(&negative)?;
    validate_states(&states)?;
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
            "session response proof",
        )?;
        validate_sd_jwt(scenario)?;
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
