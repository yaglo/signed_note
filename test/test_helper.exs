# ML-DSA-44 needs OpenSSL 3.5 or later under OTP's crypto, which many
# systems do not have. The library refuses those keys cleanly rather than
# crashing, so the suite runs either way: the tests that exercise the type
# are skipped where it is missing, and the tests that assert the refusal
# are skipped where it is present.
mldsa44? = SignedNote.SignatureType.supported?(:mldsa44_cosignature_v1)

capability = if mldsa44?, do: [:mldsa44_unavailable], else: [:mldsa44]

unless mldsa44? do
  IO.puts(:stderr, """
  \nML-DSA-44 is not available in this build's OpenSSL, so its tests are \
  skipped and the tests for refusing it run instead.\
  """)
end

ExUnit.start(exclude: [:go_differential | capability])
