{-# OPTIONS --safe --without-K #-}

module GraniteHandoff where

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Artifact : Set where
  kernel push crest : Artifact

data Verified : Artifact -> Set where
  verifiedKernel : Verified kernel
  verifiedPush : Verified push
  verifiedCrest : Verified crest

data Handoff : Set where
  measuredHandoff : Verified kernel -> Verified push -> Verified crest -> Handoff

data MissingKernelHandoff : Set where

missingKernelCannotHandoff : Not MissingKernelHandoff
missingKernelCannotHandoff ()

data FirmwareState : Set where
  bootServices liveKernel : FirmwareState

data Transition : FirmwareState -> FirmwareState -> Set where
  exitWithMeasuredBundle : Handoff -> Transition bootServices liveKernel

noUnmeasuredExit : Not (Transition liveKernel bootServices)
noUnmeasuredExit ()
