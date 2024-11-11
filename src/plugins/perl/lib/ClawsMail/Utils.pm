package ClawsMail::Utils;

use 5.024001;
use warnings;

our $VERSION = "0.20";

use parent qw(Exporter);
our @EXPORT = (
    qw(SA_is_spam extract_addresses move_to_trash abort),
    qw(addr_in_addressbook from_in_addressbook),
    qw(get_attribute_value make_sure_folder_exists),
    qw(make_sure_tag_exists get_tags),
    );

# Spam
sub SA_is_spam {
    my $retval = !ClawsMail::Filter::Matcher::test ("spamc -c < %F > /dev/null") and
        ClawsMail::C::filter_log ("LOG_MATCH", "SA_is_spam");
    return $retval;
    } # SA_is_spam

# simple extract email addresses from a header field
sub extract_addresses {
    my $hf = shift or return;
    my @addr = ();
    while ($hf =~ m/[-.+\w]+\@[-.+\w]+/) {
        $hf =~ s/^.*?([-.+\w]+\@[-.+\w]+)// and push @addr => $1;
        }
    @addr or push @addr => "";
    return @addr;
    } # extract_addresses

# move to trash
sub move_to_trash {
    ClawsMail::C::move_to_trash     ();
    ClawsMail::Filter::Action::stop (1);
    }

# make sure a folder with a given id exists
sub make_sure_folder_exists {
    ClawsMail::C::make_sure_folder_exists (@_);
    }

sub make_sure_tag_exists {
    ClawsMail::C::make_sure_tag_exists (@_);
    }

sub get_tags {
    ClawsMail::C::get_tags (@_);
    }

# abort: stop() and do not continue with built-in filtering
sub abort {
    ClawsMail::C::abort             ();
    ClawsMail::Filter::Action::stop (1);
    }

# addressbook query
sub addr_in_addressbook {
    return @_ ? ClawsMail::C::addr_in_addressbook (@_) : 0;
    }

sub from_in_addressbook {
    my ($from) = extract_addresses (ClawsMail::Filter::Matcher::header ("from"));
    return $from ? addr_in_addressbook ($from, @_) : 0;
    }

sub get_attribute_value {
    my ($email, $key) = @_;
    return $email && $key ? ClawsMail::C::get_attribute_value ($email, $key, @_) : "";
    }

1;
