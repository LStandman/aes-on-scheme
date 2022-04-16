
; SHEBANG

; RIJNDAEL CIPHER
; FIPS 197
; Nk=8 Nb=4 Nr=14

; PRELIMINARIES

(define-syntax --xor
  (syntax-rules ()
    ((--xor N1 N2)
      (bitwise-xor N1 N2))))

(define-syntax --and
  (syntax-rules ()
    ((--and N1 N2)
      (bitwise-and N1 N2))))

(define-syntax --ashift
  (syntax-rules ()
    ((--ashift N1 N2)
      (arithmetic-shift N1 N2))))

(define-syntax hi-nibble (syntax-rules ()
  ((hi-nibble N) (--ashift N -4))))

(define-syntax lo-nibble (syntax-rules ()
  ((lo-nibble N) (--and N #x0f))))

(define-syntax vv-ref
  (syntax-rules ()
    ((vv-ref V R C)
      (vector-ref (vector-ref V C) R))))

(define-syntax --plus
  (syntax-rules ()
    ((--plus N1 N2)
      (--xor N1 N2))))

(define (xtime N)
  (let ((product (--ashift N 1)))
    (if (positive? (--and product #x100))
      (--xor product #x11b)
      product)))

(define (--dot N1 N2)
  (if (zero? N2)
    0
    (let
      ( (product (--dot (xtime N1) (--ashift N2 -1))))
      (if (positive? (--and N2 1))
        (--plus N1 product)
        product))))

; CIPHER

(define (sub-word V)
  (let
      ; fig. 7
    ( (s-box '#(
        #(#x63 #xca #xb7 #x04 #x09 #x53 #xd0 #x51 #xcd #x60 #xe0 #xe7 #xba #x70 #xe1 #x8c)
        #(#x7c #x82 #xfd #xc7 #x83 #xd1 #xef #xa3 #x0c #x81 #x32 #xc8 #x78 #x3e #xf8 #xa1)
        #(#x77 #xc9 #x93 #x23 #x2c #x00 #xaa #x40 #x13 #x4f #x3a #x37 #x25 #xb5 #x98 #x89)
        #(#x7b #x7d #x26 #xc3 #x1a #xed #xfb #x8f #xec #xdc #x0a #x6d #x2e #x66 #x11 #x0d)
        #(#xf2 #xfa #x36 #x18 #x1b #x20 #x43 #x92 #x5f #x22 #x49 #x8d #x1c #x48 #x69 #xbf)
        #(#x6b #x59 #x3f #x96 #x6e #xfc #x4d #x9d #x97 #x2a #x06 #xd5 #xa6 #x03 #xd9 #xe6)
        #(#x6f #x47 #xf7 #x05 #x5a #xb1 #x33 #x38 #x44 #x90 #x24 #x4e #xb4 #xf6 #x8e #x42)
        #(#xc5 #xf0 #xcc #x9a #xa0 #x5b #x85 #xf5 #x17 #x88 #x5c #xa9 #xc6 #x0e #x94 #x68)
        #(#x30 #xad #x34 #x07 #x52 #x6a #x45 #xbc #xc4 #x46 #xc2 #x6c #xe8 #x61 #x9b #x41)
        #(#x01 #xd4 #xa5 #x12 #x3b #xcb #xf9 #xb6 #xa7 #xee #xd3 #x56 #xdd #x35 #x1e #x99)
        #(#x67 #xa2 #xe5 #x80 #xd6 #xbe #x02 #xda #x7e #xb8 #xac #xf4 #x74 #x57 #x87 #x2d)
        #(#x2b #xaf #xf1 #xe2 #xb3 #x39 #x7f #x21 #x3d #x14 #x62 #xea #x1f #xb9 #xe9 #x0f)
        #(#xfe #x9c #x71 #xeb #x29 #x4a #x50 #x10 #x64 #xde #x91 #x65 #x4b #x86 #xce #xb0)
        #(#xd7 #xa4 #xd8 #x27 #xe3 #x4c #x3c #xff #x5d #x5e #x95 #x7a #xbd #xc1 #x55 #x54)
        #(#xab #x72 #x31 #xb2 #x2f #x58 #x9f #xf3 #x19 #x0b #xe4 #xae #x8b #x1d #x28 #xbb)
        #(#x76 #xc0 #x15 #x75 #x84 #xcf #xa8 #xd2 #x73 #xdb #x79 #x08 #x8a #x9e #xdf #x16)))
      (N0 (vector-ref V 0))
      (N1 (vector-ref V 1))
      (N2 (vector-ref V 2))
      (N3 (vector-ref V 3)))
    `#(
      ,(vv-ref s-box (hi-nibble N0) (lo-nibble N0))
      ,(vv-ref s-box (hi-nibble N1) (lo-nibble N1))
      ,(vv-ref s-box (hi-nibble N2) (lo-nibble N2))
      ,(vv-ref s-box (hi-nibble N3) (lo-nibble N3)))))

(define (sub-bytes VV)
  `#(
    ,(sub-word (vector-ref VV 0))
    ,(sub-word (vector-ref VV 1))
    ,(sub-word (vector-ref VV 2))
    ,(sub-word (vector-ref VV 3))))

(define (inv-sub-bytes VV)
  (let
      ; fig. 14
    ( (s-box '#(
        #(#x52 #x7c #x54 #x08 #x72 #x6c #x90 #xd0 #x3a #x96 #x47 #xfc #x1f #x60 #xa0 #x17)
        #(#x09 #xe3 #x7b #x2e #xf8 #x70 #xd8 #x2c #x91 #xac #xf1 #x56 #xdd #x51 #xe0 #x2b)
        #(#x6a #x39 #x94 #xa1 #xf6 #x48 #xab #x1e #x11 #x74 #x1a #x3e #xa8 #x7f #x3b #x04)
        #(#xd5 #x82 #x32 #x66 #x64 #x50 #x00 #x8f #x41 #x22 #x71 #x4b #x33 #xa9 #x4d #x7e)
        #(#x30 #x9b #xa6 #x28 #x86 #xfd #x8c #xca #x4f #xe7 #x1d #xc6 #x88 #x19 #xae #xba)
        #(#x36 #x2f #xc2 #xd9 #x68 #xed #xbc #x3f #x67 #xad #x29 #xd2 #x07 #xb5 #x2a #x77)
        #(#xa5 #xff #x23 #x24 #x98 #xb9 #xd3 #x0f #xdc #x35 #xc5 #x79 #xc7 #x4a #xf5 #xd6)
        #(#x38 #x87 #x3d #xb2 #x16 #xda #x0a #x02 #xea #x85 #x89 #x20 #x31 #x0d #xb0 #x26)
        #(#xbf #x34 #xee #x76 #xd4 #x5e #xf7 #xc1 #x97 #xe2 #x6f #x9a #xb1 #x2d #xc8 #xe1)
        #(#x40 #x8e #x4c #x5b #xa4 #x15 #xe4 #xaf #xf2 #xf9 #xb7 #xdb #x12 #xe5 #xeb #x69)
        #(#xa3 #x43 #x95 #xa2 #x5c #x46 #x58 #xbd #xcf #x37 #x62 #xc0 #x10 #x7a #xbb #x14)
        #(#x9e #x44 #x0b #x49 #xcc #x57 #x05 #x03 #xce #xe8 #x0e #xfe #x59 #x9f #x3c #x63)
        #(#x81 #xc4 #x42 #x6d #x5d #xa7 #xb8 #x01 #xf0 #x1c #xaa #x78 #x27 #x93 #x83 #x55)
        #(#xf3 #xde #xfa #x8b #x65 #x8d #xb3 #x13 #xb4 #x75 #x18 #xcd #x80 #xc9 #x53 #x21)
        #(#xd7 #xe9 #xc3 #xd1 #xb6 #x9d #x45 #x8a #xe6 #xdf #xbe #x5a #xec #x9c #x99 #x0c)
        #(#xfb #xcb #x4e #x25 #x92 #x84 #x06 #x6b #x73 #x6e #x1b #xf4 #x5f #xef #x61 #x7d)))
      (N00 (vv-ref VV 0 0)) (N10 (vv-ref VV 1 0)) (N20 (vv-ref VV 2 0)) (N30 (vv-ref VV 3 0))
      (N01 (vv-ref VV 0 1)) (N11 (vv-ref VV 1 1)) (N21 (vv-ref VV 2 1)) (N31 (vv-ref VV 3 1))
      (N02 (vv-ref VV 0 2)) (N12 (vv-ref VV 1 2)) (N22 (vv-ref VV 2 2)) (N32 (vv-ref VV 3 2))
      (N03 (vv-ref VV 0 3)) (N13 (vv-ref VV 1 3)) (N23 (vv-ref VV 2 3)) (N33 (vv-ref VV 3 3)))
    `#(
      #(
        ,(vv-ref s-box (hi-nibble N00) (lo-nibble N00))
        ,(vv-ref s-box (hi-nibble N10) (lo-nibble N10))
        ,(vv-ref s-box (hi-nibble N20) (lo-nibble N20))
        ,(vv-ref s-box (hi-nibble N30) (lo-nibble N30)))
      #(
        ,(vv-ref s-box (hi-nibble N01) (lo-nibble N01))
        ,(vv-ref s-box (hi-nibble N11) (lo-nibble N11))
        ,(vv-ref s-box (hi-nibble N21) (lo-nibble N21))
        ,(vv-ref s-box (hi-nibble N31) (lo-nibble N31)))
      #(
        ,(vv-ref s-box (hi-nibble N02) (lo-nibble N02))
        ,(vv-ref s-box (hi-nibble N12) (lo-nibble N12))
        ,(vv-ref s-box (hi-nibble N22) (lo-nibble N22))
        ,(vv-ref s-box (hi-nibble N32) (lo-nibble N32)))
      #(
        ,(vv-ref s-box (hi-nibble N03) (lo-nibble N03))
        ,(vv-ref s-box (hi-nibble N13) (lo-nibble N13))
        ,(vv-ref s-box (hi-nibble N23) (lo-nibble N23))
        ,(vv-ref s-box (hi-nibble N33) (lo-nibble N33))))))

(define (shift-rows VV)
  `#(
    #(,(vv-ref VV 0 0) ,(vv-ref VV 1 1) ,(vv-ref VV 2 2) ,(vv-ref VV 3 3))
    #(,(vv-ref VV 0 1) ,(vv-ref VV 1 2) ,(vv-ref VV 2 3) ,(vv-ref VV 3 0))
    #(,(vv-ref VV 0 2) ,(vv-ref VV 1 3) ,(vv-ref VV 2 0) ,(vv-ref VV 3 1))
    #(,(vv-ref VV 0 3) ,(vv-ref VV 1 0) ,(vv-ref VV 2 1) ,(vv-ref VV 3 2))))

(define (inv-shift-rows VV)
  `#(
    #(,(vv-ref VV 0 0) ,(vv-ref VV 1 3) ,(vv-ref VV 2 2) ,(vv-ref VV 3 1))
    #(,(vv-ref VV 0 1) ,(vv-ref VV 1 0) ,(vv-ref VV 2 3) ,(vv-ref VV 3 2))
    #(,(vv-ref VV 0 2) ,(vv-ref VV 1 1) ,(vv-ref VV 2 0) ,(vv-ref VV 3 3))
    #(,(vv-ref VV 0 3) ,(vv-ref VV 1 2) ,(vv-ref VV 2 1) ,(vv-ref VV 3 0))))

(define (mix-columns VV)
  (letrec-syntax
    ( (mix-byte~ (syntax-rules ()
        ((mix-byte~ dot02 dot03 dot01 dot001)
          (--plus (--plus (--plus  (--dot dot02 #x02) (--dot dot03 #x03)) dot01) dot001))))
      (mix-byte0 (syntax-rules ()
        ((mix-byte0 C) (mix-byte~ (vv-ref VV 0 C) (vv-ref VV 1 C) (vv-ref VV 2 C) (vv-ref VV 3 C)))))
      (mix-byte1 (syntax-rules ()
        ((mix-byte1 C) (mix-byte~ (vv-ref VV 1 C) (vv-ref VV 2 C) (vv-ref VV 3 C) (vv-ref VV 0 C)))))
      (mix-byte2 (syntax-rules ()
        ((mix-byte2 C) (mix-byte~ (vv-ref VV 2 C) (vv-ref VV 3 C) (vv-ref VV 0 C) (vv-ref VV 1 C)))))
      (mix-byte3 (syntax-rules ()
        ((mix-byte3 C) (mix-byte~ (vv-ref VV 3 C) (vv-ref VV 0 C) (vv-ref VV 1 C) (vv-ref VV 2 C)))))
      (mix-word (syntax-rules ()
        ((mix-word C) `#(,(mix-byte0 C) ,(mix-byte1 C) ,(mix-byte2 C) ,(mix-byte3 C))))))
    `#( ,(mix-word 0) ,(mix-word 1) ,(mix-word 2) ,(mix-word 3))))

(define (inv-mix-columns VV)
  (letrec-syntax
    ( (mix-byte~ (syntax-rules ()
        ((mix-byte~ dot0e dot0b dot0d dot09)
          (--plus (--plus (--plus  (--dot dot0e #x0e) (--dot dot0b #x0b)) (--dot dot0d #x0d)) (--dot dot09 #x09)))))
      (mix-byte0 (syntax-rules ()
        ((mix-byte0 C) (mix-byte~ (vv-ref VV 0 C) (vv-ref VV 1 C) (vv-ref VV 2 C) (vv-ref VV 3 C)))))
      (mix-byte1 (syntax-rules ()
        ((mix-byte1 C) (mix-byte~ (vv-ref VV 1 C) (vv-ref VV 2 C) (vv-ref VV 3 C) (vv-ref VV 0 C)))))
      (mix-byte2 (syntax-rules ()
        ((mix-byte2 C) (mix-byte~ (vv-ref VV 2 C) (vv-ref VV 3 C) (vv-ref VV 0 C) (vv-ref VV 1 C)))))
      (mix-byte3 (syntax-rules ()
        ((mix-byte3 C) (mix-byte~ (vv-ref VV 3 C) (vv-ref VV 0 C) (vv-ref VV 1 C) (vv-ref VV 2 C)))))
      (mix-word (syntax-rules ()
        ((mix-word C) `#(,(mix-byte0 C) ,(mix-byte1 C) ,(mix-byte2 C) ,(mix-byte3 C))))))
    `#( ,(mix-word 0) ,(mix-word 1) ,(mix-word 2) ,(mix-word 3))))

(define (xor-word V1 V2)
  `#(
    ,(--xor (vector-ref V1 0) (vector-ref V2 0))
    ,(--xor (vector-ref V1 1) (vector-ref V2 1))
    ,(--xor (vector-ref V1 2) (vector-ref V2 2))
    ,(--xor (vector-ref V1 3) (vector-ref V2 3))))

(define (xor-columns VV1 VV2)
  `#(
    ,(xor-word (vector-ref VV1 0) (vector-ref VV2 0))
    ,(xor-word (vector-ref VV1 1) (vector-ref VV2 1))
    ,(xor-word (vector-ref VV1 2) (vector-ref VV2 2))
    ,(xor-word (vector-ref VV1 3) (vector-ref VV2 3))))

; KEY EXPANSION

(define (key-expansion~ VV1 V2)
  (let*
    ( (W0 ( xor-word V2 (vector-ref VV1 0)))
      (W1 ( xor-word W0 (vector-ref VV1 1)))
      (W2 ( xor-word W1 (vector-ref VV1 2))))
    `#(
      ,W0
      ,W1
      ,W2
      ,(    xor-word W2 (vector-ref VV1 3)))))

(define (key-expansion VV1 VV2 NR)
  (let
    ( (U (sub-word (vector-ref VV2 3))))
    (if (positive? (--and NR #x01))
      (key-expansion~ VV1 U)
      (let
        ( (rcon `,(vector-ref '#(#x01 #x02 #x04 #x08 #x10 #x20 #x40 #x80 #x1b #x36) (--ashift NR -1))))
        (key-expansion~ VV1 `#( ,(--xor (vector-ref U 1) rcon)
                                ,(vector-ref U 2)
                                ,(vector-ref U 3)
                                ,(vector-ref U 0)))))))

; ALGORITHM

(define (cipher~ VV1 UU1 UU2 NR)
  (let
    ( (VV2 (mix-columns (shift-rows (sub-bytes (xor-columns VV1 UU1)))))
      (UU3 (key-expansion UU1 UU2 NR)))
    (if (< NR 12)
      (cipher~ VV2 UU2 UU3 (+ NR 1))
      (xor-columns
        (shift-rows (sub-bytes (xor-columns VV2 UU2)))
        UU3))))

(define (cipher VV UU1 UU2)
  (cipher~ VV UU1 UU2 0))

(define (inv-cipher~ VV1 UU1 UU2 NR)
  (if (< NR 13)
    (let*
      ( (UU3 (key-expansion UU1 UU2 NR))
        (VV2 (inv-cipher~ VV1 UU2 UU3 (+ NR 1))))
      (xor-columns (inv-sub-bytes (inv-shift-rows (inv-mix-columns VV2))) UU1))
    (xor-columns
      (inv-sub-bytes (inv-shift-rows (xor-columns VV1 UU2)))
      UU1)))

(define (inv-cipher VV UU1 UU2)
  (inv-cipher~ VV UU1 UU2 0))

(define (16->4x4 V)
  `#(
    #(,(vector-ref V 00) ,(vector-ref V 01) ,(vector-ref V 02) ,(vector-ref V 03))
    #(,(vector-ref V 04) ,(vector-ref V 05) ,(vector-ref V 06) ,(vector-ref V 07))
    #(,(vector-ref V 08) ,(vector-ref V 09) ,(vector-ref V 10) ,(vector-ref V 11))
    #(,(vector-ref V 12) ,(vector-ref V 13) ,(vector-ref V 14) ,(vector-ref V 15))))

(define (4x4->16 VV)
  `#(
    ,(vv-ref VV 0 0) ,(vv-ref VV 1 0) ,(vv-ref VV 2 0) ,(vv-ref VV 3 0)
    ,(vv-ref VV 0 1) ,(vv-ref VV 1 1) ,(vv-ref VV 2 1) ,(vv-ref VV 3 1)
    ,(vv-ref VV 0 2) ,(vv-ref VV 1 2) ,(vv-ref VV 2 2) ,(vv-ref VV 3 2)
    ,(vv-ref VV 0 3) ,(vv-ref VV 1 3) ,(vv-ref VV 2 3) ,(vv-ref VV 3 3)))

(define (32->2x4x4 V)
  `#(
    #(
      #(,(vector-ref V 00) ,(vector-ref V 01) ,(vector-ref V 02) ,(vector-ref V 03))
      #(,(vector-ref V 04) ,(vector-ref V 05) ,(vector-ref V 06) ,(vector-ref V 07))
      #(,(vector-ref V 08) ,(vector-ref V 09) ,(vector-ref V 10) ,(vector-ref V 11))
      #(,(vector-ref V 12) ,(vector-ref V 13) ,(vector-ref V 14) ,(vector-ref V 15)))
    #(
      #(,(vector-ref V 16) ,(vector-ref V 17) ,(vector-ref V 18) ,(vector-ref V 19))
      #(,(vector-ref V 20) ,(vector-ref V 21) ,(vector-ref V 22) ,(vector-ref V 23))
      #(,(vector-ref V 24) ,(vector-ref V 25) ,(vector-ref V 26) ,(vector-ref V 27))
      #(,(vector-ref V 28) ,(vector-ref V 29) ,(vector-ref V 30) ,(vector-ref V 31)))))

; TEST VECTORS

; KEY EXPANSION

; A.3
(define (test-key-expansion1)
  (let*
    ( (R00 (32->2x4x4 '#( #x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                          #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7 #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4)))
      (R02 (key-expansion (vector-ref R00 0) (vector-ref R00 1) 00))
      (R03 (key-expansion (vector-ref R00 1) R02 01))
      (R04 (key-expansion R02 R03 02))
      (R05 (key-expansion R03 R04 03))
      (R06 (key-expansion R04 R05 04))
      (R07 (key-expansion R05 R06 05))
      (R08 (key-expansion R06 R07 06))
      (R09 (key-expansion R07 R08 07))
      (R10 (key-expansion R08 R09 08))
      (R11 (key-expansion R09 R10 09))
      (R12 (key-expansion R10 R11 10))
      (R13 (key-expansion R11 R12 11))
      (R14 (key-expansion R12 R13 12)))
    (and  (equal? R02 '#( #(#x9b #xa3 #x54 #x11)
                          #(#x8e #x69 #x25 #xaf)
                          #(#xa5 #x1a #x8b #x5f)
                          #(#x20 #x67 #xfc #xde)))
          (equal? R03 '#( #(#xa8 #xb0 #x9c #x1a)
                          #(#x93 #xd1 #x94 #xcd)
                          #(#xbe #x49 #x84 #x6e)
                          #(#xb7 #x5d #x5b #x9a)))
          (equal? R04 '#( #(#xd5 #x9a #xec #xb8)
                          #(#x5b #xf3 #xc9 #x17)
                          #(#xfe #xe9 #x42 #x48)
                          #(#xde #x8e #xbe #x96)))
          (equal? R05 '#( #(#xb5 #xa9 #x32 #x8a)
                          #(#x26 #x78 #xa6 #x47)
                          #(#x98 #x31 #x22 #x29)
                          #(#x2f #x6c #x79 #xb3)))
          (equal? R06 '#( #(#x81 #x2c #x81 #xad)
                          #(#xda #xdf #x48 #xba)
                          #(#x24 #x36 #x0a #xf2)
                          #(#xfa #xb8 #xb4 #x64)))
          (equal? R07 '#( #(#x98 #xc5 #xbf #xc9)
                          #(#xbe #xbd #x19 #x8e)
                          #(#x26 #x8c #x3b #xa7)
                          #(#x09 #xe0 #x42 #x14)))
          (equal? R08 '#( #(#x68 #x00 #x7b #xac)
                          #(#xb2 #xdf #x33 #x16)
                          #(#x96 #xe9 #x39 #xe4)
                          #(#x6c #x51 #x8d #x80)))
          (equal? R09 '#( #(#xc8 #x14 #xe2 #x04)
                          #(#x76 #xa9 #xfb #x8a)
                          #(#x50 #x25 #xc0 #x2d)
                          #(#x59 #xc5 #x82 #x39)))
          (equal? R10 '#( #(#xde #x13 #x69 #x67)
                          #(#x6c #xcc #x5a #x71)
                          #(#xfa #x25 #x63 #x95)
                          #(#x96 #x74 #xee #x15)))
          (equal? R11 '#( #(#x58 #x86 #xca #x5d)
                          #(#x2e #x2f #x31 #xd7)
                          #(#x7e #x0a #xf1 #xfa)
                          #(#x27 #xcf #x73 #xc3)))
          (equal? R12 '#( #(#x74 #x9c #x47 #xab)
                          #(#x18 #x50 #x1d #xda)
                          #(#xe2 #x75 #x7e #x4f)
                          #(#x74 #x01 #x90 #x5a)))
          (equal? R13 '#( #(#xca #xfa #xaa #xe3)
                          #(#xe4 #xd5 #x9b #x34)
                          #(#x9a #xdf #x6a #xce)
                          #(#xbd #x10 #x19 #x0d)))
          (equal? R14 '#( #(#xfe #x48 #x90 #xd1)
                          #(#xe6 #x18 #x8d #x0b)
                          #(#x04 #x6d #xf3 #x44)
                          #(#x70 #x6c #x63 #x1e))))))

; C.3
(define (test-key-expansion2)
  (let*
    ( (R00 (32->2x4x4 '#( #x00 #x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08 #x09 #x0a #x0b #x0c #x0d #x0e #x0f
                          #x10 #x11 #x12 #x13 #x14 #x15 #x16 #x17 #x18 #x19 #x1a #x1b #x1c #x1d #x1e #x1f)))
      (R02 (key-expansion (vector-ref R00 0) (vector-ref R00 1) 00))
      (R03 (key-expansion (vector-ref R00 1) R02 01))
      (R04 (key-expansion R02 R03 02))
      (R05 (key-expansion R03 R04 03))
      (R06 (key-expansion R04 R05 04))
      (R07 (key-expansion R05 R06 05))
      (R08 (key-expansion R06 R07 06))
      (R09 (key-expansion R07 R08 07))
      (R10 (key-expansion R08 R09 08))
      (R11 (key-expansion R09 R10 09))
      (R12 (key-expansion R10 R11 10))
      (R13 (key-expansion R11 R12 11))
      (R14 (key-expansion R12 R13 12)))
    (and  (equal? (4x4->16 R02) '#(#xa5 #x73 #xc2 #x9f #xa1 #x76 #xc4 #x98 #xa9 #x7f #xce #x93 #xa5 #x72 #xc0 #x9c))
          (equal? (4x4->16 R03) '#(#x16 #x51 #xa8 #xcd #x02 #x44 #xbe #xda #x1a #x5d #xa4 #xc1 #x06 #x40 #xba #xde))
          (equal? (4x4->16 R04) '#(#xae #x87 #xdf #xf0 #x0f #xf1 #x1b #x68 #xa6 #x8e #xd5 #xfb #x03 #xfc #x15 #x67))
          (equal? (4x4->16 R05) '#(#x6d #xe1 #xf1 #x48 #x6f #xa5 #x4f #x92 #x75 #xf8 #xeb #x53 #x73 #xb8 #x51 #x8d))
          (equal? (4x4->16 R06) '#(#xc6 #x56 #x82 #x7f #xc9 #xa7 #x99 #x17 #x6f #x29 #x4c #xec #x6c #xd5 #x59 #x8b))
          (equal? (4x4->16 R07) '#(#x3d #xe2 #x3a #x75 #x52 #x47 #x75 #xe7 #x27 #xbf #x9e #xb4 #x54 #x07 #xcf #x39))
          (equal? (4x4->16 R08) '#(#x0b #xdc #x90 #x5f #xc2 #x7b #x09 #x48 #xad #x52 #x45 #xa4 #xc1 #x87 #x1c #x2f))
          (equal? (4x4->16 R09) '#(#x45 #xf5 #xa6 #x60 #x17 #xb2 #xd3 #x87 #x30 #x0d #x4d #x33 #x64 #x0a #x82 #x0a))
          (equal? (4x4->16 R10) '#(#x7c #xcf #xf7 #x1c #xbe #xb4 #xfe #x54 #x13 #xe6 #xbb #xf0 #xd2 #x61 #xa7 #xdf))
          (equal? (4x4->16 R11) '#(#xf0 #x1a #xfa #xfe #xe7 #xa8 #x29 #x79 #xd7 #xa5 #x64 #x4a #xb3 #xaf #xe6 #x40))
          (equal? (4x4->16 R12) '#(#x25 #x41 #xfe #x71 #x9b #xf5 #x00 #x25 #x88 #x13 #xbb #xd5 #x5a #x72 #x1c #x0a))
          (equal? (4x4->16 R13) '#(#x4e #x5a #x66 #x99 #xa9 #xf2 #x4f #xe0 #x7e #x57 #x2b #xaa #xcd #xf8 #xcd #xea))
          (equal? (4x4->16 R14) '#(#x24 #xfc #x79 #xcc #xbf #x09 #x79 #xe9 #x37 #x1a #xc2 #x3c #x6d #x68 #xde #x36)))))

; MIX COLUMNS

; B
(define (test-mix-columns1)
  (and  (equal?
          (mix-columns '#(  #(#xd4 #xbf #x5d #x30)
                            #(#xe0 #xb4 #x52 #xae)
                            #(#xb8 #x41 #x11 #xf1)
                            #(#x1e #x27 #x98 #xe5)))
          '#( #(#x04 #x66 #x81 #xe5)
              #(#xe0 #xcb #x19 #x9a)
              #(#x48 #xf8 #xd3 #x7a)
              #(#x28 #x06 #x26 #x4c)))
        (equal?
          (mix-columns '#(  #(#x49 #xdb #x87 #x3b)
                            #(#x45 #x39 #x53 #x89)
                            #(#x7f #x02 #xd2 #xf1)
                            #(#x77 #xde #x96 #x1a)))
          '#( #(#x58 #x4d #xca #xf1)
              #(#x1b #x4b #x5a #xac)
              #(#xdb #xe7 #xca #xa8)
              #(#x1b #x6b #xb0 #xe5)))
        (equal?
          (mix-columns '#(  #(#xac #xc1 #xd6 #xb8)
                            #(#xef #xb5 #x5a #x7b)
                            #(#x13 #x23 #xcf #xdf)
                            #(#x45 #x73 #x11 #xb5)))
          '#( #(#x75 #xec #x09 #x93)
              #(#x20 #x0b #x63 #x33)
              #(#x53 #xc0 #xcf #x7c)
              #(#xbb #x25 #xd0 #xdc)))
        (equal?
          (mix-columns '#(  #(#x52 #xa4 #xc8 #x94)
                            #(#x85 #x11 #x6a #x28)
                            #(#xe3 #xcf #x2f #xd7)
                            #(#xf6 #x50 #x5e #x07)))
          '#( #(#x0f #xd6 #xda #xa9)
              #(#x60 #x31 #x38 #xbf)
              #(#x6f #xc0 #x10 #x6b)
              #(#x5e #xb3 #x13 #x01)))
        (equal?
          (mix-columns '#(  #(#xe1 #xfb #x96 #x7c)
                            #(#xe8 #xc8 #xae #x9b)
                            #(#x35 #x6c #xd2 #xba)
                            #(#x97 #x4f #xfb #x53)))
          '#( #(#x25 #xd1 #xa9 #xad)
              #(#xbd #x11 #xd1 #x68)
              #(#xb6 #x3a #x33 #x8e)
              #(#x4c #x4c #xc0 #xb0)))
        (equal?
          (mix-columns '#(  #(#xa1 #x4f #x3d #xfe)
                            #(#x78 #xe8 #x03 #xfc)
                            #(#x10 #xd5 #xa8 #xdf)
                            #(#x4c #x63 #x29 #x23)))
          '#( #(#x4b #x86 #x8d #x6d)
              #(#x2c #x4a #x89 #x80)
              #(#x33 #x9d #xf4 #xe8)
              #(#x37 #xd2 #x18 #xd8)))
        (equal?
          (mix-columns '#(  #(#xf7 #x83 #x40 #x3f)
                            #(#x27 #x43 #x3d #xf0)
                            #(#x9b #xb5 #x31 #xff)
                            #(#x54 #xab #xa9 #xd3)))
          '#( #(#x14 #x15 #xb5 #xbf)
              #(#x46 #x16 #x15 #xec)
              #(#x27 #x46 #x56 #xd7)
              #(#x34 #x2a #xd8 #x43)))
        (equal?
          (mix-columns '#(  #(#xbe #x3b #xd4 #xfe)
                            #(#xd4 #xe1 #xf2 #xc8)
                            #(#x0a #x64 #x2c #xc0)
                            #(#xda #x83 #x86 #x4d)))
          '#( #(#x00 #x51 #x2f #xd1)
              #(#xb1 #xc8 #x89 #xff)
              #(#x54 #x76 #x6d #xcd)
              #(#xfa #x1b #x99 #xea)))
        (equal?
          (mix-columns '#(  #(#x87 #x6e #x46 #xa6)
                            #(#xf2 #x4c #xe7 #x8c)
                            #(#x4d #x90 #x4a #xd8)
                            #(#x97 #xec #xc3 #x95)))
          '#( #(#x47 #x37 #x94 #xed)
              #(#x40 #xd4 #xe4 #xa5)
              #(#xa3 #x70 #x3a #xa6)
              #(#x4c #x9f #x42 #xbc)))))

; C.1
(define (test-mix-columns2)
  (and  (equal?
          (mix-columns (16->4x4 '#(#x63 #x53 #xe0 #x8c #x09 #x60 #xe1 #x04 #xcd #x70 #xb7 #x51 #xba #xca #xd0 #xe7)))
          (16->4x4 '#(#x5f #x72 #x64 #x15 #x57 #xf5 #xbc #x92 #xf7 #xbe #x3b #x29 #x1d #xb9 #xf9 #x1a)))
        (equal?
          (mix-columns (16->4x4 '#(#xa7 #xbe #x1a #x69 #x97 #xad #x73 #x9b #xd8 #xc9 #xca #x45 #x1f #x61 #x8b #x61)))
          (16->4x4 '#(#xff #x87 #x96 #x84 #x31 #xd8 #x6a #x51 #x64 #x51 #x51 #xfa #x77 #x3a #xd0 #x09)))
        (equal?
          (mix-columns (16->4x4 '#(#x3b #xd9 #x22 #x68 #xfc #x74 #xfb #x73 #x57 #x67 #xcb #xe0 #xc0 #x59 #x0e #x2d)))
          (16->4x4 '#(#x4c #x9c #x1e #x66 #xf7 #x71 #xf0 #x76 #x2c #x3f #x86 #x8e #x53 #x4d #xf2 #x56)))
        (equal?
          (mix-columns (16->4x4 '#(#x2d #x6d #x7e #xf0 #x3f #x33 #xe3 #x34 #x09 #x36 #x02 #xdd #x5b #xfb #x12 #xc7)))
          (16->4x4 '#(#x63 #x85 #xb7 #x9f #xfc #x53 #x8d #xf9 #x97 #xbe #x47 #x8e #x75 #x47 #xd6 #x91)))
        (equal?
          (mix-columns (16->4x4 '#(#x36 #x33 #x9d #x50 #xf9 #xb5 #x39 #x26 #x9f #x2c #x09 #x2d #xc4 #x40 #x6d #x23)))
          (16->4x4 '#(#xf4 #xbc #xd4 #x54 #x32 #xe5 #x54 #xd0 #x75 #xf1 #xd6 #xc5 #x1d #xd0 #x3b #x3c)))
        (equal?
          (mix-columns (16->4x4 '#(#xe8 #xda #xb6 #x90 #x14 #x77 #xd4 #x65 #x3f #xf7 #xf5 #xe2 #xe7 #x47 #xdd #x4f)))
          (16->4x4 '#(#x98 #x16 #xee #x74 #x00 #xf8 #x7f #x55 #x6b #x2c #x04 #x9c #x8e #x5a #xd0 #x36)))
        (equal?
          (mix-columns (16->4x4 '#(#xb4 #x58 #x12 #x4c #x68 #xb6 #x8a #x01 #x4b #x99 #xf8 #x2e #x5f #x15 #x55 #x4c)))
          (16->4x4 '#(#xc5 #x7e #x1c #x15 #x9a #x9b #xd2 #x86 #xf0 #x5f #x4b #xe0 #x98 #xc6 #x34 #x39)))
        (equal?
          (mix-columns (16->4x4 '#(#x3e #x1c #x22 #xc0 #xb6 #xfc #xbf #x76 #x8d #xa8 #x50 #x67 #xf6 #x17 #x04 #x95)))
          (16->4x4 '#(#xba #xa0 #x3d #xe7 #xa1 #xf9 #xb5 #x6e #xd5 #x51 #x2c #xba #x5f #x41 #x4d #x23)))
        (equal?
          (mix-columns (16->4x4 '#(#x54 #xd9 #x90 #xa1 #x6b #xa0 #x9a #xb5 #x96 #xbb #xf4 #x0e #xa1 #x11 #x70 #x2f)))
          (16->4x4 '#(#xe9 #xf7 #x4e #xec #x02 #x30 #x20 #xf6 #x1b #xf2 #xcc #xf2 #x35 #x3c #x21 #xc7)))))

; SHIFT ROWS

; B
(define (test-shift-rows1)
  (and  (equal?
          (shift-rows '#( #(#xd4 #x27 #x11 #xae)
                          #(#xe0 #xbf #x98 #xf1)
                          #(#xb8 #xb4 #x5d #xe5)
                          #(#x1e #x41 #x52 #x30)))
          '#( #(#xd4 #xbf #x5d #x30)
              #(#xe0 #xb4 #x52 #xae)
              #(#xb8 #x41 #x11 #xf1)
              #(#x1e #x27 #x98 #xe5)))
        (equal?
          (shift-rows '#( #(#x49 #xde #xd2 #x89)
                          #(#x45 #xdb #x96 #xf1)
                          #(#x7f #x39 #x87 #x1a)
                          #(#x77 #x02 #x53 #x3b)))
          '#( #(#x49 #xdb #x87 #x3b)
              #(#x45 #x39 #x53 #x89)
              #(#x7f #x02 #xd2 #xf1)
              #(#x77 #xde #x96 #x1a)))
        (equal?
          (shift-rows '#( #(#xac #x73 #xcf #x7b)
                          #(#xef #xc1 #x11 #xdf)
                          #(#x13 #xb5 #xd6 #xb5)
                          #(#x45 #x23 #x5a #xb8)))
          '#( #(#xac #xc1 #xd6 #xb8)
              #(#xef #xb5 #x5a #x7b)
              #(#x13 #x23 #xcf #xdf)
              #(#x45 #x73 #x11 #xb5)))
        (equal?
          (shift-rows '#( #(#x52 #x50 #x2f #x28)
                          #(#x85 #xa4 #x5e #xd7)
                          #(#xe3 #x11 #xc8 #x07)
                          #(#xf6 #xcf #x6a #x94)))
          '#( #(#x52 #xa4 #xc8 #x94)
              #(#x85 #x11 #x6a #x28)
              #(#xe3 #xcf #x2f #xd7)
              #(#xf6 #x50 #x5e #x07)))
        (equal?
          (shift-rows '#( #(#xe1 #x4f #xd2 #x9b)
                          #(#xe8 #xfb #xfb #xba)
                          #(#x35 #xc8 #x96 #x53)
                          #(#x97 #x6c #xae #x7c)))
          '#( #(#xe1 #xfb #x96 #x7c)
              #(#xe8 #xc8 #xae #x9b)
              #(#x35 #x6c #xd2 #xba)
              #(#x97 #x4f #xfb #x53)))
        (equal?
          (shift-rows '#( #(#xa1 #x63 #xa8 #xfc)
                          #(#x78 #x4f #x29 #xdf)
                          #(#x10 #xe8 #x3d #x23)
                          #(#x4c #xd5 #x03 #xfe)))
          '#( #(#xa1 #x4f #x3d #xfe)
              #(#x78 #xe8 #x03 #xfc)
              #(#x10 #xd5 #xa8 #xdf)
              #(#x4c #x63 #x29 #x23)))
        (equal?
          (shift-rows '#( #(#xf7 #xab #x31 #xf0)
                          #(#x27 #x83 #xa9 #xff)
                          #(#x9b #x43 #x40 #xd3)
                          #(#x54 #xb5 #x3d #x3f)))
          '#( #(#xf7 #x83 #x40 #x3f)
              #(#x27 #x43 #x3d #xf0)
              #(#x9b #xb5 #x31 #xff)
              #(#x54 #xab #xa9 #xd3)))
        (equal?
          (shift-rows '#( #(#xbe #x83 #x2c #xc8)
                          #(#xd4 #x3b #x86 #xc0)
                          #(#x0a #xe1 #xd4 #x4d)
                          #(#xda #x64 #xf2 #xfe)))
          '#( #(#xbe #x3b #xd4 #xfe)
              #(#xd4 #xe1 #xf2 #xc8)
              #(#x0a #x64 #x2c #xc0)
              #(#xda #x83 #x86 #x4d)))
        (equal?
          (shift-rows '#( #(#x87 #xec #x4a #x8c)
                          #(#xf2 #x6e #xc3 #xd8)
                          #(#x4d #x4c #x46 #x95)
                          #(#x97 #x90 #xe7 #xa6)))
          '#( #(#x87 #x6e #x46 #xa6)
              #(#xf2 #x4c #xe7 #x8c)
              #(#x4d #x90 #x4a #xd8)
              #(#x97 #xec #xc3 #x95)))
        (equal?
          (shift-rows '#( #(#xe9 #x09 #x89 #x72)
                          #(#xcb #x31 #x07 #x5f)
                          #(#x3d #x32 #x7d #x94)
                          #(#xaf #x2e #x2c #xb5)))
          '#( #(#xe9 #x31 #x7d #xb5)
              #(#xcb #x32 #x2c #x72)
              #(#x3d #x2e #x89 #x5f)
              #(#xaf #x09 #x07 #x94)))))

(define (test-main)
  (begin
    (display (format "test-key-expansion1 - ~a~%" (if (test-key-expansion1) "PASS" "FAIL")))
    (display (format "test-key-expansion2 - ~a~%" (if (test-key-expansion2) "PASS" "FAIL")))
    (display (format "test-mix-columns1   - ~a~%" (if (test-mix-columns1)   "PASS" "FAIL")))
    (display (format "test-mix-columns2   - ~a~%" (if (test-mix-columns2)   "PASS" "FAIL")))
    (display (format "test-shift-rows1    - ~a~%" (if (test-shift-rows1)    "PASS" "FAIL")))))


;(display (format "~a~%" (cipher
;  '#(
;    #(#x00 #x11 #x22 #x33)
;    #(#x44 #x55 #x66 #x77)
;    #(#x88 #x99 #xaa #xbb)
;    #(#xcc #xdd #xee #xff))
;  '#(
;    #(#x00 #x01 #x02 #x03)
;    #(#x04 #x05 #x06 #x07)
;    #(#x08 #x09 #x0a #x0b)
;    #(#x0c #x0d #x0e #x0f))
;  '#(
;    #(#x10 #x11 #x12 #x13)
;    #(#x14 #x15 #x16 #x17)
;    #(#x18 #x19 #x1a #x1b)
;    #(#x1c #x1d #x1e #x1f)))))
;
;(display (format "~a~%" (inv-cipher (cipher
;  '#(
;    #(#x00 #x11 #x22 #x33)
;    #(#x44 #x55 #x66 #x77)
;    #(#x88 #x99 #xaa #xbb)
;    #(#xcc #xdd #xee #xff))
;  '#(
;    #(#x00 #x01 #x02 #x03)
;    #(#x04 #x05 #x06 #x07)
;    #(#x08 #x09 #x0a #x0b)
;    #(#x0c #x0d #x0e #x0f))
;  '#(
;    #(#x10 #x11 #x12 #x13)
;    #(#x14 #x15 #x16 #x17)
;    #(#x18 #x19 #x1a #x1b)
;    #(#x1c #x1d #x1e #x1f)))
;  '#(
;    #(#x00 #x01 #x02 #x03)
;    #(#x04 #x05 #x06 #x07)
;    #(#x08 #x09 #x0a #x0b)
;    #(#x0c #x0d #x0e #x0f))
;  '#(
;    #(#x10 #x11 #x12 #x13)
;    #(#x14 #x15 #x16 #x17)
;    #(#x18 #x19 #x1a #x1b)
;    #(#x1c #x1d #x1e #x1f)))))


(test-main)
