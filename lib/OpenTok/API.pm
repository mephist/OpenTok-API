package OpenTok::API;

use 5.006;
use strict;
use warnings;

use Time::HiRes;
use MIME::Base64;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);

use LWP;
use XML::XPath;

use OpenTok::API::Session;
use OpenTok::API::Exceptions;

=head1 NAME

OpenTok::API - Perl SDK for OpenTok
http://www.tokbox.com/

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';
our $API_VERSION = 'tbpl-v0.01.2011-06-15';
our %API_SERVER = ( "development" => "https://staging.tokbox.com/hl",
                    "production" => "https://api.opentok.com/hl");
our %RoleConstants = (
                    "SUBSCRIBER" => "subscriber",
                    "PUBLISHER" => "publisher",
                    "MODERATOR" => "moderator",
);

=head1 SYNOPSIS

1. Generate Token

    use OpenTok::API;
    
    # Get your own API-keys from http://www.tokbox.com/opentok/api/tools/js/apikey
    my $ot = OpenTok::API->new('api_key' => '1127', 'api_secret' => '123456789sosecretcode123123123');
    
    print $ot->generate_token()."\n";
    ...

2. Create new session

    print $ot->create_session('location' => '127.0.0.1')->getSessionId();
    
    

=head1 SUBROUTINES/METHODS

=head2 new

Creates and returns a new OpenTok::API object

    my $ot = OpenTok::API->new('api_key' => '1127', 'api_secret' => '123456789sosecretcode123123123');

=over 4

=item * C<< api_key => string >>

Sets your TokBox API Partner Key

=item * C<< api_secret => string >>

Sets your TokBox API Partner Secret 

=item * C<< mode => "development|"production" >>

Set it to "production" when you launch your app in production. Default is "development".

=back

=cut

sub new {
    my ($class, %args) = @_;
    my $self = {
        api_key => exists $args{api_key} ? $args{api_key} : '_api_key_',
        api_secret => exists $args{api_secret} ? $args{api_secret} : '_api_secret_',
        api_mode => exists $args{mode} ? $args{mode} : 'development',
    };
    
    bless $self, $class;
    
    return $self;
}

=head2 generate_token

Generates a token for specific session.

    $ot->generate_token(session_id => '153975e9d3ecce1d11baddd2c9d8d3c9d147df18', role => 'moderator' );

=over 4

=item * C<< session_id => string >>

If session_id is not blank, this token can only join the call with the specified session_id.

=item * C<< role => "subscriber"|"publisher"|"moderator" >>

One of the roles. Default is publisher, look in the documentation to learn more about roles.
http://www.tokbox.com/opentok/api/tools/as3/documentation/overview/token_creation.html

=item * C<< expire_time => int >>

Optional. The time when the token will expire, defined as an integer value for a Unix timestamp (in seconds).
If you do not specify this value, tokens expire in 24 hours after being created.
The expiration_time value, if specified, must be within seven days of the creation time.

=back

=cut

sub generate_token {
    my $self = shift;
    my %arg = (
        session_id => '',
        role => $RoleConstants{PUBLISHER},
        expire_time => undef,
        @_,        
    );
    
    my $create_time = time();
    my $nonce = Time::HiRes::time . rand(2147483647);
    
    my $query_string = "session_id=".$arg{session_id}."&create_time=".$create_time."&role=".$arg{role}."&nonce=".$nonce;
    
    $query_string .= "&expire_time=${arg{expire_time}}" if ($arg{expire_time});
    
    my $signature = $self->_sign_string($query_string, $self->{api_secret});
    
    my $api_key = $self->{api_key};
    
    my $sdk_version = $API_VERSION;
    
    return "T1==" . encode_base64("partner_id=$api_key&sdk_version=$sdk_version&sig=$signature:$query_string",'');
     
}

=head2 create_session

Creates and returns OpenTok::API::Session object

    $ot->create_session(location => $ENV{'REMOTE_ADDR'});

=over 4

=item * C<< location => string >>

An IP address that TokBox will use to situate the session in its global network.
Ideally, this IP address should be representative of the geographical locations of the participants in the session.
If you have access to the IP address of the first participant in the session, use that address.

=item * C<< echoSuppression_enabled => [0|1] >>

Whether echo suppression is initially enabled for multiplexed streams. The default value is 0.

=item * C<< multiplexer_numOutputStreams => int >>

The number of multiplexed streams automatically created for the session. The default value is 0.

=item * C<< multiplexer_switchType => int >>

An integer defining the type of multiplexer-based switch:
0 for a timeout-based switch;
1 for an activity-based switch.
The default value is 0 (timeout-based).

=item * C<< multiplexer_switchTimeout => int >>

The length, in milliseconds, for the switch in a timeout-based multiplexer.
The minimum value is 2000 (2 seconds), and the server will change lower values to 2000.
The default value is 5000 (5 seconds).

Created OpenTok::API::Session object includes a sessionID method, which returns the session ID for the new session.
Use this session ID in JavaScript on the page that you serve to the client.
The JavaScript will use this value when calling the connect() method of the Session object (to connect a user to an OpenTok session).

=back

=cut

sub create_session {
    my $self = shift;
    my %arg = (
        location => '',
        api_key => $self->{api_key},
        @_,
    );
    my $session_raw = $self->_do_request("/session/create", %arg);
    my $session_xml;
    
    eval {
       $session_xml = XML::XPath->new( xml => $session_raw ) or OpenTok::API::Exception->throw( error => "Failed to create session: Invalid response from server: $!" );
    };    
    
    return if (Exception::Class->caught('OpenTok::API::Exception'));
    
    if($session_xml->exists('/Errors')) {
        my $err_msg = $session_xml->find('//@message');
        $err_msg = 'Unknown error' unless $err_msg;
        
        OpenTok::API::Exception::Auth->throw(error => "Error " . $session_xml->find('//@code') ." ". $session_xml->find('local-name(//error/*[1])') . ": " . $err_msg );
        
        return;       
    }
    
    return OpenTok::API::Session->new( map {  $_->getName => $_->string_value } $session_xml->find('//Session/*')->get_nodelist);       
    
}

# private methods

sub _sign_string {
    my $self = shift;
    my ($query_string, $api_secret) =  @_;
    return hmac_sha1_hex($query_string, $api_secret);    
}


sub _do_request {
    my $self = shift;
    my $cmd = shift;
    my %arg = (
      @_,       
    );
    
    my $url = $API_SERVER{$self->{api_mode}}.$cmd;
    
    my $data =  join '&', map { "$_=".$self->_urlencode($arg{$_}) } keys %arg;
    
    my $ua = LWP::UserAgent->new;
    #$ua->agent("$0/0.1 " . $ua->agent);
    
    my $request = HTTP::Request->new(POST => $url);
    $request->header('X-TB-PARTNER-AUTH' => $self->{api_key}.':'.$self->{api_secret});
    $request->content_type('application/x-www-form-urlencoded');
    $request->content($data);
    
    my $result = $ua->request($request);

    if ($result->is_success) {
          return $result->content;
    }
    else {
       OpenTok::API::Exception::Auth->throw( error => "Request error: ".$result->status_line );
       return;
    }

}

sub _urlencode {
    my ($self, $data) = @_;

    $data =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
    return $data;    
}

=head1 AUTHOR

Maxim Nikolenko, C<< <root at zbsd.ru> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-opentok-api at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=OpenTok::API>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc OpenTok::API

You can also look for information at:

http://www.tokbox.com/opentok/api/tools/as3/documentation/overview/index.html

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=OpenTok::API>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/OpenTok-API>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/OpenTok-API>

=item * Search CPAN

L<http://search.cpan.org/dist/OpenTok-API/>

=back


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Maxim Nikolenko.

This module is released under the following license: BSD


=cut

1; # End of OpenTok
