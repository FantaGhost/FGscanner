#!/usr/bin/perl -w

# FantaGhost URL Scanner 1.1
# Last update: 2014-02-01

use LWP::UserAgent;
use Getopt::Long;
use IO::Socket::PortState qw(check_ports);

my $dirlist="fg_dirs.txt";       
my $pagelist="fg_pages.txt";     
my $ualist="fg_ua.lst";
my $useragent="FGscanner/1.1 (Cli; FGscanner-Perl; CrossPlatform; rv:1.1) Perl-FGscanner/20140201";
my $delay=0;              	 
my $maxdelay=30;
my $httpout=15;		         
my $pidFile="/var/run/fgscan.pid";
my $proxyFile="";
my $host="";
my $dump="";
my $logdir="";

my $args = GetOptions(
	"debug"			=> \$debug,
	"help"			=> \$help,
	"dirs=s"		=> \$dirlist,
        "pages=s"		=> \$pagelist,
        "proxy=s"               => \$proxyFile,
        "uarnd"                 => \$uarnd,
	"host=s"		=> \$host,
	"sec=s"			=> \$delay,
        "dump"                  => \$dump,
        "tor"                   => \$tor,
        "tordns"                => \$tordns
);

my $ua = new LWP::UserAgent;
my $ua2 = new LWP::UserAgent;

$istor=0;

if ($help) {
	print <<__HELP__;
fgscan 1.0
Usage: $0 --host <hostname> [--proxy=filepath] [--uarnd] [--sec=n] [--dump] [--dirlist=filepath] [--wordlist=filepath] [--tor] [--tordns] [--debug] [--help]

Where:
--debug    : Print debug information
--dirs     : Specify the directory list file
--pages    : Specify the wordlist file
--uarnd    : Enable User-Agent randomization
--host     : Specify hostname to scan (hostname only without http:// or https://)
--proxy    : Specify a proxy list
--sec	   : Seconds between requests. Value 999 will randomize delay between requests from 1 to 30 seconds
--dump     : Save found pages on disk
--tor      : Use TOR as proxy for each request
--tordns   : Use TOR to resolve hostname. Without this options DNS queries will be directed to default DNS server outside TOR network.
--help     : What you're reading now
__HELP__
	exit 0;
}

die "Directories list not found.\n" unless (-e $dirlist);
die "Pages list not found.\n" unless (-e $pagelist);
die "User Agent list not found.\n" unless (-e $ualist);
die "You must specify an hostname to scan. Please run --help for more information.\n" unless $host ne "";

($debug) && print "+++ Debug Mode Activated +++ \n";
($debug) && print "--- Selected hostname: ".$host."\n";
($debug) && print "--- Directories list: ".$dirlist."\n";
($debug) && print "--- Pages list: ".$pagelist."\n";
($debug) && print "--- Delay: ".$delay."\n";
($debug) && ($uarnd) && print "--- User Agent Randomization Enabled\n";
($debug) && (!$uarnd) && print "--- User Agent: ".$useragent."\n";
($debug) && print "--- HTTP TimeOut: ".$httpout." seconds.\n";
($tor) && CheckTor();
($debug) && print "--- Tor usage is set to ".$istor."\n";

open my $dirs, $dirlist or die "Could not open $file: $!";

if ($proxyFile) {
   (-r $proxyFile) or die "Cannot read proxy configuration file $proxyFile: $!";
   loadProxyFromFile($proxyFile) || die "Cannot load proxies from file $proxyFile";
} else {
   ($debug) && print "--- No proxy configured...\n";
}

if ($tordns) {
    $hostip=`tor-resolve $host`;
    ($debug) && print $host." resolved via tor to ".$hostip."\n";
    $host=$hostip;
}

($debug) && sleep(2);

print "\nStarting scan on ".$host."\n";

while( my $line = <$dirs>) {
      
      unless($line =~ /^\s*$/) {
    
      if ($uarnd) {
         $useragent = RandomUa();
      }  

      ($debug) && print "\nDirectory readed ".$line;
      
      if ($delay == 999) {
         $delayrand=int(rand($maxdelay));
         ($debug) && print "Waiting ".$delayrand." second...\n";
         sleep($delayrand);
      }
      else {
        sleep($delay);
      }
      if (@proxies) {
          $tempProxy = selectRandomProxy();
          $ua->proxy('http', $useragent);
          ($debug) && print "Proxy used: ".$tempProxy."\n";
      }
      if ($istor==1) {
          $ua->proxy('http', 'socks://localhost:9050'); # Tor proxy
          ($debug) && print "Proxy used: TOR\n";
      }
      $ua->agent($useragent);
      ($debug) && print "User Agent : ".$useragent;
      $ua->timeout($httpout);
      $http_request="http://".$host."/".$line;     
      $http_request=~ tr/\r\n//d;
      ($debug) && print "Request created ".$http_request."\n";
      $timestamp=localtime;
      my $response = $ua->get($http_request);
      ($debug) && print "Response ".$response."\n";
      ($debug) && print $timestamp." ";
      print $http_request;
      if ($response->is_success) {
         print " ---> ".$response->status_line."\n";
         logit($http_request.",".$response->status_line);
         open my $pages, $pagelist or die "Could not open $file: $!";
         while (my $line2 = <$pages>) { 
            unless($line2 =~ /^\s*$/) {
               if (@proxies) {
                  $tempProxy2 = selectRandomProxy();
                  $ua2->proxy('http', $tempProxy2);
                  ($debug) && print ("Proxy used: ".$tempProxy2."\n");
               }
               if ($istor==1) {
                   $ua->proxy('http', 'socks://localhost:9050'); # Tor proxy
                   ($debug) && print "Proxy used: TOR\n";
               }
               ($debug) && print "\nPage readed ".$line2;
               ($debug) && print "LWP Object created ".$ua."\n";
               $ua2->agent($useragent);
               ($debug) && print "User Agent set ".$useragent."\n";
               $ua2->timeout($httpout);
               my $http_request2=$http_request."/".$line2;
               $http_request2=~ tr/\r\n//d;
               $timestamp=localtime;
               ($debug) && print "Request created ".$http_request2."\n";
               my $response2 = $ua->get($http_request2);
               ($debug) && print "Response ".$response2."\n";
               ($debug) && print $timestamp." ";
               print $http_request2;
               if ($response2->is_success) {
                  print " ---> ".$response2->status_line."\n";
                  logit($http_request2.",".$response2->status_line);
                  if ($dump) {
                     $filesave=$host."_".$line2;
                     open (MYPAGE,">$filesave");
                     print MYPAGE $response->decoded_content;
                     close (MYPAGE);
                  }
               }
               else {
                  print " ---> ".$response2->status_line."\n";    
               }
            } 
         }
      close $pages;               
      }
      else {
            print " ---> ".$response->status_line."\n";
            logit($http_request.",".$response->status_line);
           }
   }
}
close $dirs;
exit 0;


# Original logit subroutine created by http://jeredsutton.com/2010/07/18/simple-perl-logging-subroutine/ 
sub logit
{
    my $s = shift;
    my ($logsec,$logmin,$loghour,$logmday,$logmon,$logyear,$logwday,$logyday,$logisdst)=localtime(time);
    my $logtimestamp = sprintf("%4d-%02d-%02d,%02d:%02d:%02d",$logyear+1900,$logmon+1,$logmday,$loghour,$logmin,$logsec);
    $logmon++;
    $logyear=$logyear+1900;
    my $logfile="$logdir$logyear-$logmon-$logmday-fgscan.log";
    my $fh;
    open($fh, '>>', "$logfile") or die "$logfile: $!";
    print $fh "$logtimestamp,$s\n";
    close($fh);
}

sub loadProxyFromFile {
        my $file = shift;
        return(1) unless defined($file);
        open(PROXY_FD, "$file") || die "Cannot open file $file : $!";
        while(<PROXY_FD>) {
                chomp;
                (length > 0) && push(@proxies, 'http://'.$_);
                ($debug) && print ("Proxy loaded: ".$_."\n");
        }
        close(PROXY_FD);
        (@proxies) || die "No proxies read from $file";
        print("Loaded " . @proxies . " proxies from " . $file."\n\n");
        return(1);
}

sub selectRandomProxy {
        my $randomIdx = rand($#proxies);
        return $proxies[$randomIdx];
}

sub CheckTor {
        my $proto   = 'tcp';
        my $port    = '9050';
        my $address = '127.0.0.1'; 

        my($section, $ping_timeout, %porthash);
        $porthash{$proto}{$port}{'name'} = $section;
        check_ports($address, $ping_timeout, \%porthash);

        my $open = $porthash{$proto}{$port}{'open'};
        if ($open) {
           $istor=1;
        }     
        else {
           $istor=0;
           print "ERROR! Check that TOR daemon is running and port 9050 is available...\n";
           exit 1;
        }
}

sub RandomUa {
       my $text="";
       open(UALST,"$ualist") or die "Can't open `$ualist': $!";
       while ($text ne $useragent) {
          srand();
          rand($.) < 1 && ($text = $_) while <UALST>;
          $useragent = $text;
       }
       close(UALST);
       sleep(3);
       return($text);
}

