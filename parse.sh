#!/bin/awk -f
function logData (offset) {

  attributes="sub-rule-number|anchor|tracker|real-interface|reason|action|direction|ip-version";

  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf(">\n");
  if ( $9 == "4" ) {
    ipv4SpecificData(offset+n);
  } else if ( $9 == "6" ) {
    ipv6SpecificData(offset+n);
  }
  printf("    </log-data>\n");

}

function ipv4SpecificData (offset) {

  attributes="tos|ecn|ttl|id|offset|flags|protocol-id|protocol-text|length|source-address|destination-address";

  printf("      <ipv4-specific-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf(">\n"); 
  if ( $17 == "tcp" ) {
    tcpData(offset+n);
  } else if ( $17 == "udp" ) {
    udpData(offset+n);
  } else if ( $17 == "icmp" ) {
    icmpData(offset+n);
  } else if ( $17 == "carp" ) {
    carpData(offset+n);
  }
  printf("      </ipv4-specific-data>\n");
}

function tcpData (offset) {

  attributes="source-port|destination-port|data-length|tcp-flags|sequence-number|ack-number|tcp-window|ur|tcp-options";

  printf("        <tcp-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function udpData (offset) {

  attributes="source-port|destination-port|data-length";

  printf("        <udp-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpData (offset) {

  attributes="icmp-type";

  printf("        <icmp-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf(">\n"); 
  if ( $21 == "maskreply" ) {
    icmpOtherUnreachableData(offset+n);
  } else if ( $21 == "needfrag" ) {
    icmpNeedfragData(offset+n);
  } else if ( $21 == "paramprob" ) {
    icmpOtherUnreachableData(offset+n);
  } else if ( $21 == "redirect" ) {
    icmpOtherUnreachableData(offset+n);
  } else if ( $21 == "reply" ) {
    icmpEchoData(offset+n);
  } else if ( $21 == "request" ) {
    icmpEchoData(offset+n);
  } else if ( $21 == "timexceed" ) {
    icmpOtherUnreachableData(offset+n);
  } else if ( $21 == "tstamp" ) {
    icmpTstampData(offset+n);
  } else if ( $21 == "tstampreply" ) {
    icmpTstampreplyData(offset+n);
  } else if ( $21 == "unreach" ) {
    icmpOtherUnreachableData(offset+n);
  } else if ( $21 == "unreachport" ) {
    icmpUnreachportData(offset+n);
  } else if ( $21 == "unreachproto" ) {
    icmpUnreachprotoData(offset+n);
  }
  printf("        </icmp-data>\n");
}

function icmpEchoData (offset) {

  attributes="echo-id|echo-sequence";

  printf("        <echo-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpUnreachprotoData (offset) {

  attributes="icmp-destination-ip-address|unreachable-protocol-id";

  printf("        <unreachproto-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpUnreachportData (offset) {

  attributes="icmp-destination-ip-address|unreachable-protocol-id|unreachable-port-number";

  printf("        <unreachport-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpOtherUnreachableData (offset) {

  attributes="icmp-description";

  printf("        <other-unreachable-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpNeedfragData (offset) {

  attributes="icmp-destination-ip-address|icmp-mtu";

  printf("        <needfrag-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpTstampData (offset) {

  attributes="icmp-id|icmp-sequence";

  printf("        <tstamp-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpTstampreplyData (offset) {

  attributes="icmp-otime|icmp-rtime|icmp-ttime";

  printf("        <tstampreply-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function icmpDefaultData (offset) {

  attributes="icmp-description";

  printf("        <icmp-default-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function carpData (offset) {

  attributes="carp-type|carp-ttl|vhid|version|advbase|advskew";

  printf("        <carp-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf("/>\n"); 
}

function ipv6SpecificData (offset) {

  attributes="class|flow-label|hop-limit|protocol-text|protocol-id|length|source-address|destination-address";

  printf("      <ipv6-specific-data");
  n=split(attributes,a,"|");
  for ( i=1; i <= n; i++) {
    if ( $(i+offset) != "" ) {
      printf(" %s=\"%s\"",a[i], $(i+offset));
    }
  }
  printf(">\n"); 
  if ( $13 == "tcp" ) {
    tcpData(offset+n);
  } else if ( $13 == "UDP" ) {
    udpData(offset+n);
  } else if ( $13 == "icmp" ) {
    icmpData(offset+n);
  } else if ( $13 == "carp" ) {
    carpData(offset+n);
  }
  printf("      </ipv6-specific-data>\n");
}
BEGIN {

  printf("<root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n");
}
{
  FS=",";
  split($1,fl," ")
  
  if ( fl[3] == "filterlog:" ) {
    printf("  <log-entry timestamp=\"%s\" hostname=\"%s\">\n", fl[1], fl[2]);
    printf("    <log-data");
    
    
    if ( fl[4] != "" )
      printf(" rule-number=\"%s\"", fl[4]);
      
    logData(1);

    printf("  </log-entry>\n");
  }
}
END {
  printf("</root>\n");
}
