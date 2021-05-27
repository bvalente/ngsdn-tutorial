package org.onosproject.ngsdn.tutorial.common;

import com.fasterxml.jackson.databind.JsonNode;

import org.onlab.packet.Ip4Address;

public class VxlanConfig {

    // TODO public to private
    public Ip4Address segment;
    public int vni;
    public Ip4Address vtepIp;
    public Ip4Address nexthop;

    VxlanConfig( JsonNode node ) {

        segment = Ip4Address.valueOf( node.get("segment").asText() );
        vni = node.get("vni").intValue();
        vtepIp = Ip4Address.valueOf( node.get("vtepIp").asText() );
        nexthop = Ip4Address.valueOf( node.get("nexthop").asText() );

    }

}
