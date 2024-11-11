package ClawsMail::Persistent;

use 5.024001;
use warnings;

our $VERSION = "0.20";

use Symbol qw(delete_package);

our %Cache;

sub valid_package_name {
    my ($string) = @_;
    $string =~ s{([^A-Za-z0-9/])}{sprintf "_%2x", unpack "C", $1}eg;
    # second pass only for words starting with a digit
    $string =~ s{/([0-9])}{sprintf "/_%2x", unpack "C", $1}eg;

    # Dress it up as a real package name
    $string =~ s{/}{::}g;
    return "ClawsMail" . $string;
    } # valid_package_name

sub eval_file {
    my ($file, $delete) = @_;
    my $package = valid_package_name ($file);
    my $mtime   = (lstat $file)[9];
    if ($mtime >= ($Cache{$package}{mtime} // 0)) {
        defined $Cache{$package}{mtime} and delete_package ($package);
        open my $fh, "<", $file or die "Failed to open $file: $!\n";
        my $sub = do { local $/; <$fh> };
        close $fh;
        #wrap the code into a subroutine inside our unique package
        my $eval = qq{
            package $package;
            use ClawsMail::Filter::Matcher;
            use ClawsMail::Filter::Action;
            use ClawsMail::Utils;
            sub handler { $sub; }
            };
        {   # hide our variables within this block
            my ($file, $mtime, $package, $sub);
            eval $eval;
            }
        $@ and die $@;
        #cache it unless we"re cleaning out each time
        $delete or $Cache{$package}{mtime} = $mtime;
        }
    eval { $package->handler; };
    $@      and die $@;
    $delete and delete_package ($package);
    } # eval_file

1;
