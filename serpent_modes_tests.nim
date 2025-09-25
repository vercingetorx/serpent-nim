import std/unittest

import ../serpent

suite "Serpent modes sanity":
  test "ECB roundtrip":
    let key = fromHex("00112233445566778899aabbccddeeff")
    var data = newSeq[byte](32)
    for i in 0 ..< data.len: data[i] = byte(i)
    let ctx = newSerpentEcbCtx(key)
    let ct = ctx.encrypt(data)
    let pt = ctx.decrypt(ct)
    check pt == data

  test "CBC roundtrip":
    let key = fromHex("000102030405060708090a0b0c0d0e0f")
    let iv  = fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    var data = newSeq[byte](48)
    for i in 0 ..< data.len: data[i] = byte(i * 3)
    var ctx = newSerpentCbcCtx(key, iv)
    let ct = ctx.encrypt(data)
    let pt = ctx.decrypt(ct)
    check pt == data

  test "CTR roundtrip":
    let key = fromHex("00112233445566778899aabbccddeeff")
    let nonce = fromHex("0001020304050607")
    var enc = newSerpentCtrCtx(key, nonce)
    var dec = newSerpentCtrCtx(key, nonce)
    var msg = newSeq[byte](37)
    for i in 0 ..< msg.len: msg[i] = byte(255 - i)
    # single-call encryption/decryption (matches AES port semantics)
    let ct = enc.encrypt(msg)
    let pt = dec.decrypt(ct)
    check pt == msg

  test "GCM AEAD roundtrip + tag check":
    let key = fromHex("000102030405060708090a0b0c0d0e0f")
    let iv  = fromHex("000102030405060708090a0b") # 12 bytes
    var gcm = newSerpentGcmCtx(key, iv)
    let aad = fromHex("0a0b0c0d0e0f")
    var msg = newSeq[byte](24)
    for i in 0 ..< msg.len: msg[i] = byte(i xor 0xA5)
    let (ct, tag) = gcm.encrypt(aad, msg)
    let pt = gcm.decrypt(aad, ct, tag)
    check pt == msg
    # Tamper tag
    var badTag = tag
    badTag[0] = badTag[0] xor 1
    expect ValueError:
      discard gcm.decrypt(aad, ct, badTag)

  test "GCM-SIV AEAD roundtrip + tag check":
    let key = fromHex("000102030405060708090a0b0c0d0e0f")
    let nonce = fromHex("000102030405060708090a0b")
    var g = newSerpentGcmSivCtx(key, nonce)
    let aad = fromHex("aabbccdd")
    let ptIn = fromHex("00112233445566778899aabbccddeeff")
    let (ct, tag) = g.encrypt(aad, ptIn)
    let ptOut = g.decrypt(aad, ct, tag)
    check ptOut == ptIn
    var tag2 = tag
    tag2[^1] = tag2[^1] xor 0x80'u8
    expect ValueError:
      discard g.decrypt(aad, ct, tag2)

  test "XTS roundtrip including partial":
    let k1 = fromHex("000102030405060708090a0b0c0d0e0f")
    let k2 = fromHex("0f0e0d0c0b0a09080706050403020100")
    var xts = newSerpentXtsCtx(k1, k2)
    let tweak = fromHex("00112233445566778899aabbccddeeff")
    var data = newSeq[byte](40)
    for i in 0 ..< data.len: data[i] = byte(i * 7)
    let ct = xts.encrypt(tweak, data)
    let dec = xts.decrypt(tweak, ct)
    check dec == data
