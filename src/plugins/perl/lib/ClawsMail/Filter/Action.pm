package ClawsMail::Filter::Action;

use 5.024001;
use warnings;

our $VERSION = "0.20";

use parent qw(Exporter);
our @EXPORT = qw(
    mark unmark dele mark_as_unread mark_as_read
    lock unlock move copy color execute
    hide set_score change_score stop cm_exit
    forward forward_as_attachment redirect
    set_tag unset_tag clear_tags
    );
use ClawsMail::Filter::Matcher;

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
sub mark                  { ClawsMail::C::set_flag (1); }
sub unmark                { ClawsMail::C::unset_flag (1); }
sub mark_as_unread        { ClawsMail::C::set_flag (2); }
sub mark_as_read          { ClawsMail::C::unset_flag (2); }
sub lock                  { ClawsMail::C::set_flag (7); }
sub unlock                { ClawsMail::C::unset_flag (7); }
sub copy                  { ClawsMail::C::copy (@_); }
sub forward               { ClawsMail::C::forward (1, @_); }
sub forward_as_attachment { ClawsMail::C::forward (2, @_); }
sub redirect              { ClawsMail::C::redirect (@_); }
sub hide                  { ClawsMail::C::hide (); }

sub cm_exit {
    ClawsMail::C::filter_log ("LOG_ACTION", "exit");
    stop                     (1);
    } # cm_exit

sub stop {
    my $nolog = shift;
    defined $nolog
        ? die "intended"
        : ClawsMail::C::filter_log ("LOG_ACTION", "stop");
    } # stop

sub set_score {
    $ClawsMail::Filter::Matcher::msginfo{score} = ClawsMail::C::set_score (@_);
    } # set_score

sub change_score {
    $ClawsMail::Filter::Matcher::msginfo{score} = ClawsMail::C::change_score (@_);
    } # change_score

sub execute {
    my $cmd = shift or return 0;
    my $flv = ClawsMail::C::filter_log_verbosity (0);
    ClawsMail::Filter::Matcher::test   ($cmd);
    ClawsMail::C::filter_log_verbosity ($flv);
    ClawsMail::C::filter_log           ("LOG_ACTION", qq{execute: $cmd});
    1;
    } # execute

sub move { ClawsMail::C::move (@_); stop (1); }
sub dele { ClawsMail::C::delete (); stop (1); }

sub color {
    my ($color) = @_;
    $color = lc2_ $color;
    defined $colors{$color} and $color = $colors{$color};
    $color =~ m/[^0-9]/     and $color = 0;
    ClawsMail::C::color ($color);
    } # color

sub set_tag    { ClawsMail::C::set_tag    (@_); }
sub unset_tag  { ClawsMail::C::unset_tag  (@_); }
sub clear_tags { ClawsMail::C::clear_tags (@_); }

1;
