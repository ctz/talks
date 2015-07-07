use Crypt::PBKDF2;

my $iterations = 1 << 22;
my $pbkdf2 = Crypt::PBKDF2->new( iterations => $iterations );
printf "SHA1,%d,%s\n", $iterations, $pbkdf2->PBKDF2_hex("saltsalt", "password");
