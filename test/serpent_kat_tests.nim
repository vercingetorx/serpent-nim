import std/[unittest, strutils, os]

import ../serpent_core

const
  katDir = splitFile(currentSourcePath()).dir / "KATs"

proc hexToBytes(hex: string): seq[byte] =
  let cleaned = hex.strip
  if cleaned.len mod 2 != 0:
    raise newException(ValueError, "Hex string must have even length: " & cleaned)
  result = newSeq[byte](cleaned.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(cleaned[2*i .. 2*i+1]))

proc hexToBlock(hex: string): array[serpentBlockSize, byte] =
  let bytes = hexToBytes(hex)
  if bytes.len != serpentBlockSize:
    raise newException(ValueError, "Block hex length mismatch")
  for i in 0 ..< serpentBlockSize:
    result[i] = bytes[i]

proc toHexLower(data: openArray[byte]): string =
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add(b.toHex(2).toLowerAscii())

type
  KatEntry = object
    keySize: int
    keyHex: string
    ptHex: string
    ctHex: string
    ivHex: string

iterator katEntries(path: string; needsIv: bool): KatEntry =
  var keySize = 0
  var keyHex = ""
  var ptHex = ""          # per-case PT (if present in-case)
  var ctHex = ""          # per-case CT
  var ivHex = ""          # per-case IV
  var ptGlobal = ""       # PT declared outside cases (VK files)
  var ptGlobalSet = false
  var havePt = false
  var haveCt = false
  var haveIv = not needsIv
  var inCase = false
  for rawLine in path.lines:
    let line = rawLine.strip
    if line.len == 0:
      continue
    if line[0] == '=' or line.startsWith("/*") or line.startsWith("*/") or
       line.startsWith("FILENAME") or line.startsWith("Algorithm") or
       line.startsWith("Principal"):
      continue
    if line.startsWith("KEYSIZE="):
      keySize = parseInt(line.split('=')[1])
      # Reset state between key sizes
      ptGlobal = ""
      ptGlobalSet = false
      continue
    if line.startsWith("I="):
      # Start of a new case
      inCase = true
      havePt = false
      haveCt = false
      haveIv = not needsIv
      ptHex.setLen(0)
      ctHex.setLen(0)
      ivHex.setLen(0)
      continue
    if line.startsWith("KEY="):
      keyHex = line.split('=')[1]
      continue
    if line.startsWith("PT="):
      if inCase:
        ptHex = line.split('=')[1]
        havePt = true
      else:
        ptGlobal = line.split('=')[1]
        ptGlobalSet = true
    if line.startsWith("CT="):
      ctHex = line.split('=')[1]
      haveCt = true
      # fallthrough to try yield
    if needsIv and line.startsWith("IV="):
      ivHex = line.split('=')[1]
      haveIv = true
      continue
    # Emit when we are in a case and have enough info
    if inCase and haveCt and (havePt or ptGlobalSet) and (not needsIv or haveIv) and keyHex.len > 0:
      let usePt = if havePt: ptHex else: ptGlobal
      yield KatEntry(keySize: keySize, keyHex: keyHex, ptHex: usePt, ctHex: ctHex, ivHex: ivHex)
      # Reset per-case flags
      inCase = false
      haveCt = false
      havePt = false
      haveIv = not needsIv

proc runEcbKat(fileName: string; decrypt = false) =
  let path = katDir / fileName
  for entry in katEntries(path, needsIv = false):
    let keyBytes = hexToBytes(entry.keyHex)
    let schedule = initSerpentSchedule(keyBytes)
    # Monte Carlo files ("_e_m.txt" / "_d_m.txt") require 10,000 inner ops
    let isMc = fileName.contains("_e_m.txt") or fileName.contains("_d_m.txt")
    if not decrypt:
      var blk = hexToBlock(entry.ptHex)
      if isMc:
        # ECB Monte Carlo ENCRYPT: PT_{j+1} = E_k(PT_j), j in [0..9999]
        for _ in 0 ..< 10000:
          schedule.serpentEncrypt(blk)
        check toHexLower(blk) == entry.ctHex.toLowerAscii()
      else:
        schedule.serpentEncrypt(blk)
        check toHexLower(blk) == entry.ctHex.toLowerAscii()
    else:
      var blk = hexToBlock(entry.ctHex)
      if isMc:
        # ECB Monte Carlo DECRYPT: CT_{j+1} = D_k(CT_j), j in [0..9999]; compare PT
        for _ in 0 ..< 10000:
          schedule.serpentDecrypt(blk)
        check toHexLower(blk) == entry.ptHex.toLowerAscii()
      else:
        schedule.serpentDecrypt(blk)
        check toHexLower(blk) == entry.ptHex.toLowerAscii()

proc runCbcKat(fileName: string; decrypt = false) =
  let path = katDir / fileName
  for entry in katEntries(path, needsIv = true):
    let keyBytes = hexToBytes(entry.keyHex)
    let schedule = initSerpentSchedule(keyBytes)
    let ivBlock = hexToBlock(entry.ivHex)
    let isMc = fileName.contains("_e_m.txt") or fileName.contains("_d_m.txt")
    if not decrypt:
      if isMc:
        # CBC Monte Carlo ENCRYPT per NIST spec
        var pt = hexToBlock(entry.ptHex)
        var cv = ivBlock
        var lastCt: array[serpentBlockSize, byte]
        for _ in 0 ..< 10000:
          var ib: array[serpentBlockSize, byte]
          for i in 0 ..< serpentBlockSize:
            ib[i] = pt[i] xor cv[i]
          lastCt = ib
          schedule.serpentEncrypt(lastCt)
          # Prepare next iteration
          pt = cv    # PT_{j+1} = (j==0 ? CV_0 : CT_{j-1}); cv currently holds CV_j
          cv = lastCt  # CV_{j+1} = CT_j
        check toHexLower(lastCt) == entry.ctHex.toLowerAscii()
      else:
        var blk = hexToBlock(entry.ptHex)
        for i in 0 ..< serpentBlockSize:
          blk[i] = blk[i] xor ivBlock[i]
        schedule.serpentEncrypt(blk)
        check toHexLower(blk) == entry.ctHex.toLowerAscii()
    else:
      if isMc:
        # CBC Monte Carlo DECRYPT per NIST spec
        var cv = ivBlock
        var ct = hexToBlock(entry.ctHex)
        var pt: array[serpentBlockSize, byte]
        for _ in 0 ..< 10000:
          pt = ct
          schedule.serpentDecrypt(pt)
          for i in 0 ..< serpentBlockSize:
            pt[i] = pt[i] xor cv[i]
          # CV_{j+1} = CT_j; CT_{j+1} = PT_j
          cv = ct
          ct = pt
        check toHexLower(pt) == entry.ptHex.toLowerAscii()
      else:
        var blk = hexToBlock(entry.ctHex)
        schedule.serpentDecrypt(blk)
        for i in 0 ..< serpentBlockSize:
          blk[i] = blk[i] xor ivBlock[i]
        check toHexLower(blk) == entry.ptHex.toLowerAscii()

proc runEcbIvKat() =
  let path = katDir / "ecb_iv.txt"
  var keyHex = ""
  var keyBytes: seq[byte]
  var schedule: SerpentSchedule
  var waitingPt = false
  var currentPt = ""
  var doneForKey = false
  for rawLine in path.lines:
    let line = rawLine.strip
    if line.len == 0 or line[0] == '=' or line.startsWith("/*") or
       line.startsWith("FILENAME") or line.startsWith("Algorithm") or
       line.startsWith("Principal"):
      continue
    if line.startsWith("KEY="):
      keyHex = line.split('=')[1]
      keyBytes = hexToBytes(keyHex)
      schedule = initSerpentSchedule(keyBytes)
      waitingPt = false
      doneForKey = false
      continue
    if line.startsWith("PT="):
      if not doneForKey:
        currentPt = line.split('=')[1]
        waitingPt = true
      continue
    if waitingPt and line.startsWith("CT="):
      let expected = line.split('=')[1]
      var blk = hexToBlock(currentPt)
      schedule.serpentEncrypt(blk)
      check toHexLower(blk) == expected.toLowerAscii()
      waitingPt = false
      doneForKey = true

suite "Serpent KATs":
  test "ECB Monte Carlo Encrypt":
    runEcbKat("ecb_e_m.txt", decrypt = false)

  test "ECB Monte Carlo Decrypt":
    runEcbKat("ecb_d_m.txt", decrypt = true)

  test "CBC Monte Carlo Encrypt":
    runCbcKat("cbc_e_m.txt", decrypt = false)

  test "CBC Monte Carlo Decrypt":
    runCbcKat("cbc_d_m.txt", decrypt = true)

  test "ECB Variable Key":
    runEcbKat("ecb_vk.txt", decrypt = false)

  test "ECB Variable Text":
    runEcbKat("ecb_vt.txt", decrypt = false)

  test "ECB Tables":
    runEcbKat("ecb_tbl.txt", decrypt = false)

  test "ECB Intermediate Values":
    runEcbIvKat()
