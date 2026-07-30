module GraniteBoot

%default total

public export
data Artifact = Kernel | Push | Crest

public export
record DigestEvidence (artifact : Artifact) where
  constructor Measured
  expected : Bits64
  actual : Bits64

public export
data Verified : Artifact -> Type where
  Exact : (digest : Bits64) -> Verified artifact

public export
verifyDigest : DigestEvidence artifact -> Maybe (Verified artifact)
verifyDigest (Measured 0 actual) = Nothing
verifyDigest (Measured expected actual) =
  if expected == actual then Just (Exact actual) else Nothing

public export
record BootBundle where
  constructor MkBootBundle
  kernel : Verified Kernel
  push : Verified Push
  crest : Verified Crest

public export
assemble :
  DigestEvidence Kernel ->
  DigestEvidence Push ->
  DigestEvidence Crest ->
  Maybe BootBundle
assemble kernel push crest = do
  verifiedKernel <- verifyDigest kernel
  verifiedPush <- verifyDigest push
  verifiedCrest <- verifyDigest crest
  pure (MkBootBundle verifiedKernel verifiedPush verifiedCrest)
