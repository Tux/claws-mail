package ClawsMail::Filter::Matcher;

use 5.024001;
use warnings;

our $VERSION = "0.20";

use locale;
use parent qw(Exporter);
our @EXPORT = qw(
    header body filepath manual
    filter_log_verbosity filter_log
    all marked unread deleted new replied
    forwarded locked colorlabel match matchcase
    regexp regexpcase test
    to cc subject from to_or_cc newsgroups inreplyto person
    references body_part headers_part headers_cont message
    size_greater size_smaller size_equal
    score_greater score_lower score_equal
    age_greater age_lower partial tagged $permanent
    );

our (%header, $body, %msginfo, $mail_done, $manual);
our %colors = (
    "none"     => 0,
    "orange"   => 1,
    "red"      => 2,
    "pink"     => 3,
    "sky blue" => 4,
    "blue"     => 5,
    "green"    => 6,
    "brown"    => 7,
    );
# For convenience
sub lc2_         { return lc (shift // ""); }
sub to           { return "to"; }
sub cc           { return "cc"; }
sub from         { return "from"; }
sub subject      { return "subject"; }
sub to_or_cc     { return "to_or_cc"; }
sub newsgroups   { return "newsgroups"; }
sub inreplyto    { return "in-reply-to"; }
sub person       { return "person"; }
sub references   { return "references"; }
sub body_part    { return "body_part"; }
sub headers_part { return "headers_part"; }
sub headers_cont { return "headers_cont"; }
sub message      { return "message"; }
# access the mail directly
sub header {
    my $key = shift;
    unless (defined $key) {
        init_ ();
        return keys %header;
        }
    $key = lc2_ ($key);
    $key =~ s/:$//;
    $header{$key} or init_ ();
    return exists $header{$key}
        ? wantarray ? @{$header{$key}} : $header{$key}[-1]
        : undef;
    } # header
sub body     { init_ (); return $body; }
sub filepath { return $msginfo{filepath}; }

sub manual {
    $manual and ClawsMail::C::filter_log ("LOG_MATCH", "manual");
    return $manual;
    } # manual

sub filter_log {
    my ($arg1, $arg2) = @_;
    return defined $arg2
        ? ClawsMail::C::filter_log ($arg1, $arg2)
        : ClawsMail::C::filter_log ("LOG_MANUAL", $arg1);
    } # filter_log

sub filter_log_verbosity {
    my $arg = shift;
    return defined $arg
        ? ClawsMail::C::filter_log_verbosity ($arg)
        : ClawsMail::C::filter_log_verbosity ();
    } # filter_log_verbosity

# Public Matcher Tests
sub all           { ClawsMail::C::filter_log ("LOG_MATCH", "all"); return 1; }
sub marked        { return ClawsMail::C::check_flag (1); }
sub unread        { return ClawsMail::C::check_flag (2); }
sub deleted       { return ClawsMail::C::check_flag (3); }
sub new           { return ClawsMail::C::check_flag (4); }
sub replied       { return ClawsMail::C::check_flag (5); }
sub forwarded     { return ClawsMail::C::check_flag (6); }
sub locked        { return ClawsMail::C::check_flag (7); }
sub ignore_thread { return ClawsMail::C::check_flag (8); }
sub age_greater   { return ClawsMail::C::age_greater (@_); }
sub age_lower     { return ClawsMail::C::age_lower (@_); }
sub tagged        { return ClawsMail::C::tagged (@_); }

sub score_equal {
    my $my_score = shift // 0;
    if (($msginfo{score} // -1) == $my_score) {
        ClawsMail::C::filter_log ("LOG_MATCH", "score_equal");
        return 1;
        }
    return 0;
    } # score_equal

sub score_greater {
    my $my_score = shift // 0;
    if (($msginfo{score} // 0) > $my_score) {
        ClawsMail::C::filter_log ("LOG_MATCH", "score_greater");
        return 1;
        }
    return 0;
    } # score_greater

sub score_lower {
    my $my_score = shift // 0;
    if (($msginfo{score} // 0) < $my_score) {
        ClawsMail::C::filter_log ("LOG_MATCH", "score_lower");
        return 1;
        }
    return 0;
    } # score_lower

sub colorlabel {
    my $color = shift;
    $color = lc2_ ($color);
    defined $colors{$color} and $color = $colors{$color};
    $color =~ m/[^0-9]/     and $color = 0;
    return ClawsMail::C::colorlabel ($color);
    } # colorlabel

sub size_greater {
    my $my_size = shift // 0;
    if (($msginfo{size} // 0) > $my_size) {
        ClawsMail::C::filter_log ("LOG_MATCH", "size_greater");
        return 1;
        }
    return 0;
    } # size_greater

sub size_smaller {
    my $my_size = shift // 0;
    if (($msginfo{size} // 0) < $my_size) {
        ClawsMail::C::filter_log ("LOG_MATCH", "size_smaller");
        return 1;
        }
    return 0;
    } # size_smaller

sub size_equal {
    my $my_size = shift // 0;
    if (($msginfo{size} // -1) == $my_size) {
        ClawsMail::C::filter_log ("LOG_MATCH", "size_equal");
        return 1;
        }
    return 0;
    } # size_equal

sub partial {
    defined $msginfo{total_size} && defined $msginfo{size} or return 0;
    if ($msginfo{total_size} and $msginfo{size} != $msginfo{total_size}) {
        ClawsMail::C::filter_log ("LOG_MATCH", "partial");
        return 1;
        }
    return 0;
    } # partial

sub test {
    $_ = shift;
    my $command = "";
    my $hl      = "";
    my $re      = "";
    my $cmdline = $_;
    s/\\"/"/g;    #fool stupid emacs perl mode;
    s/([^%]*)//;
    $command .= $1;

    while ($_) {
        if    (m/^%%/) { s/^%%([^%]*)//; $command .= "\\%" . $1; next; }
        elsif (m/^%s/) { s/^%s([^%]*)//; $re = $1; $hl = header ("subject");    }
        elsif (m/^%f/) { s/^%f([^%]*)//; $re = $1; $hl = header ("from");       }
        elsif (m/^%t/) { s/^%t([^%]*)//; $re = $1; $hl = header ("to");         }
        elsif (m/^%c/) { s/^%c([^%]*)//; $re = $1; $hl = header ("cc");         }
        elsif (m/^%d/) { s/^%d([^%]*)//; $re = $1; $hl = header ("date");       }
        elsif (m/^%i/) { s/^%i([^%]*)//; $re = $1; $hl = header ("message-id"); }
        elsif (m/^%n/) { s/^%n([^%]*)//; $re = $1; $hl = header ("newsgroups"); }
        elsif (m/^%r/) { s/^%r([^%]*)//; $re = $1; $hl = header ("references"); }
        elsif (m/^%F/) { s/^%F([^%]*)//; $re = $1; $hl = filepath ();           }
        else           { s/^(%[^%]*)//;  $command .= $1; }
        defined $hl and $command .= "\Q$hl\E";
        $hl       = "";
        $command .= $re;
        $re       = "";
        }
    my $retval = !(system ($command) >> 8) and
        ClawsMail::C::filter_log ("LOG_MATCH", "test: $cmdline");
    return $retval;
    } # test

sub matchcase {
    my $retval = match_ (@_, "i") and
        ClawsMail::C::filter_log ("LOG_MATCH", "matchcase: $_[0], $_[1]");
    return $retval;
    } # matchcase

sub match {
    my $retval = match_ (@_) and
        ClawsMail::C::filter_log ("LOG_MATCH", "match: $_[0], $_[1]");
    return $retval;
    } # match

sub regexpcase {
    my $retval = match_ (@_, "ri") and
        ClawsMail::C::filter_log ("LOG_MATCH", "regexpcase: $_[0], $_[1]");
    return $retval;
    } # regexpcase

sub regexp {
    my $retval = match_ (@_, "r") and
        ClawsMail::C::filter_log ("LOG_MATCH", "regexp: $_[0], $_[1]");
    return $retval;
    } # regexp

# Internals
sub add_header_entries_ {
    my ($key, @values) = @_;
    $key = lc2_ ($key);
    $key =~ s/:$//;
    $header{$key} ||= [];
    push @{$header{$key}} => @values;
    } # add_header_entries

# read whole mail
sub init_ {
    $mail_done and return 0;
    ClawsMail::C::open_mail_file  ();
    read_headers_                 ();
    read_body_                    ();
    ClawsMail::C::close_mail_file ();
    $mail_done = 1;
    } # init_

sub filter_init_ {
    %header  = ();
    %msginfo = ();
    undef $body;
    $mail_done     = 0;
    $manual        = ClawsMail::C::filter_init (100);
    $msginfo{size} = ClawsMail::C::filter_init (1);
    add_header_entries_ ("date",            ClawsMail::C::filter_init (2));
    add_header_entries_ ("from",            ClawsMail::C::filter_init (3));
    add_header_entries_ ("to",              ClawsMail::C::filter_init (4));
    add_header_entries_ ("cc",              ClawsMail::C::filter_init (5));
    add_header_entries_ ("newsgroups",      ClawsMail::C::filter_init (6));
    add_header_entries_ ("subject",         ClawsMail::C::filter_init (7));
    add_header_entries_ ("msgid",           ClawsMail::C::filter_init (8));
    add_header_entries_ ("inreplyto",       ClawsMail::C::filter_init (9));
    add_header_entries_ ("xref",            ClawsMail::C::filter_init (10));
    add_header_entries_ ("xface",           ClawsMail::C::filter_init (11));
    add_header_entries_ ("dispositionnotificationto",
                                            ClawsMail::C::filter_init (12));
    add_header_entries_ ("returnreceiptto", ClawsMail::C::filter_init (13));
    add_header_entries_ ("references",      ClawsMail::C::filter_init (14));
    $msginfo{score}            = ClawsMail::C::filter_init (15);
    $msginfo{plaintext_file}   = ClawsMail::C::filter_init (17);
    $msginfo{hidden}           = ClawsMail::C::filter_init (19);
    $msginfo{filepath}         = ClawsMail::C::filter_init (20);
    $msginfo{partial_recv}     = ClawsMail::C::filter_init (21);
    $msginfo{total_size}       = ClawsMail::C::filter_init (22);
    $msginfo{account_server}   = ClawsMail::C::filter_init (23);
    $msginfo{account_login}    = ClawsMail::C::filter_init (24);
    $msginfo{planned_download} = ClawsMail::C::filter_init (25);
    } # filter_init

sub read_headers_ {
    %header = ();
    while (my ($key, $value) = ClawsMail::C::get_next_header ()) {
        $key =~ m/:$/ or next;
        add_header_entries_ ($key, $value);
        }
    } # read_headers_

sub read_body_ {
    while (defined (my $line = ClawsMail::C::get_next_body_line ())) {
        $body .= $line;
        }
    } # read_body_

sub match_ {
    my ($where, $what, $modi) = @_;
    $modi ||= "";
    my $nocase = $modi =~ m/i/ ? 1 : 0;
    my $regexp = $modi =~ m/r/ ? 1 : 0;

    if ($where eq "to_or_cc") {
        my $to = header ("to");
        my $cc = header ("cc");
        unless ($regexp) {
            return $nocase
                ?      (index (lc2_ ($to), lc2_ ($what)) != -1)
                    || (index (lc2_ ($cc), lc2_ ($what)) != -1)
                :      (index (      $to,        $what ) != -1)
                    || (index (      $cc,        $what ) != -1);
            }
        return $nocase
            ? $to =~ m/$what/i || $cc =~ m/$what/i
            : $to =~ m/$what/  || $cc =~ m/$what/;
        }

    if ($where eq "person") {
        die qq{query for $where NYI in this plugin!\n};
        }

    if ($where eq "body_part") {
        my $mybody = body () =~ s/\s+/ /gr;
        unless ($regexp) {
            return $nocase
                ? (index (lc2_ ($mybody), lc2_ ($what)) != -1)
                : (index (      $mybody,        $what ) != -1);
            }
        return $nocase ? $body =~ m/$what/i : $body =~ m/$what/;
        }

    if ($where eq "headers_part") {
        my $myheader = header_as_string_ ();
        unless ($regexp) {
            $myheader =~ s/\s+/ /g;
            return $nocase
                ? (index (lc2_ ($myheader), lc2_ ($what)) != -1)
                : (index (      $myheader,        $what ) != -1);
            }
        return $nocase ? $myheader =~ m/$what/i : $myheader =~ m/$what/;
        }

    if ($where eq "headers_cont") {
        my $myheader = header_as_string_ () =~ s/^\S+:\s*//r;
        unless ($regexp) {
            $myheader =~ s/\s+/ /g;
            return $nocase
                ? (index (lc2_ ($myheader), lc2_ ($what)) != -1)
                : (index (      $myheader,        $what ) != -1);
            }
        return $nocase ? $myheader =~ m/$what/i : $myheader =~ m/$what/;
        }

    if ($where eq "message") {
        my $message = join "\n" => header_as_string_ (), body ();
        unless ($regexp) {
            $message =~ s/\s+/ /g;
            return $nocase
                ? (index (lc2_ ($message), lc2_ ($what)) != -1)
                : (index (      $message,        $what ) != -1);
            }
        return $nocase ? $message =~ m/$what/i : $message =~ m/$what/;
        }

    if ($where eq "tag") {
        my $found = 0;
        #sub ClawsMail::Utils::get_tags;
        foreach my $tag (ClawsMail::Utils::get_tags ()) {
            $found = $regexp
                ? $nocase
                    ? $tag =~ m/$what/i
                    : $tag =~ m/$what/
                : $nocase
                    ? (index (lc2_ ($tag), lc2_ ($what)) != -1)
                    : (index (      $tag,        $what ) != -1)
                and last;
            }
        return $found;
        }

    my $myheader = header (lc2_ ($where)) or return 0;
    unless ($regexp) {
        return $nocase
            ? (index (lc2_ ($myheader), lc2_ ($what)) != -1)
            : (index (      $myheader,        $what ) != -1);
        }
    return $nocase ? $myheader =~ m/$what/i : $myheader =~ m/$what/;
    } # match_

sub header_as_string_ {
    my $headerstring = "";
    my @headerkeys   = header ();
    foreach my $field (@headerkeys) {
        $headerstring .= "$(field}: $_\n" for header ($field);
        }
    return $headerstring;
    } # header_as_string

our $permanent = "";

1;
