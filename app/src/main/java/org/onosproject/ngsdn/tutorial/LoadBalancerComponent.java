/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.ngsdn.tutorial;

import com.google.common.collect.Lists;

import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.host.HostEvent.Type;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.ngsdn.tutorial.common.FabricDeviceConfig;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.onosproject.ngsdn.tutorial.common.LoadBalancerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;
import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * App component that configures devices to provide IPv4 routing capabilities
 * across the whole fabric.
 */
@Component(
        immediate = true,
        // *** DONE EXERCISE 5
        // set to true when ready
        enabled = true
)
public class LoadBalancerComponent {

    private static final Logger log = LoggerFactory.getLogger(LoadBalancerComponent.class);

    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;

    private final HostListener hostListener = new InternalHostListener();
    private final LinkListener linkListener = new InternalLinkListener();
    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final PacketProcessor packetProcessor = new InternalPacketProcessor();

    private ApplicationId appId;

    private HashMap<String, Float> serverLoadStorage;
    private HashMap<String, String> onlineServers;

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality =  ReferenceCardinality.MANDATORY)
    private PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        serverLoadStorage = new HashMap<String, Float>();
        onlineServers = new HashMap<String, String>();

        hostService.addListener(hostListener);
        linkService.addListener(linkListener);
        deviceService.addListener(deviceListener);
        packetService.addProcessor(packetProcessor, 10);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        linkService.removeListener(linkListener);
        deviceService.removeListener(deviceListener);
        packetService.removeProcessor(packetProcessor);

        log.info("Stopped");
    }

    private void setupLoadBalancer(DeviceId deviceId){

        log.info("Adding Load Balancing Configurations to {} ...", deviceId);
        LoadBalancerConfig loadBalancerConfig = getLoadBalancerConfig(deviceId);

        //----
        //set special acl for load balancing controller packets
        PiCriterion controllerCriterion = PiCriterion.builder()
            .matchTernary(
                PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                MacAddress.valueOf("00:aa:00:00:00:ff").toBytes(),
                MacAddress.valueOf("00:aa:00:00:00:ff").toBytes())
            .build();
        PiAction cloneToCpuAction = PiAction.builder()
            .withId(PiActionId.of("IngressPipeImpl.clone_to_cpu"))
            .build();
        FlowRule aclRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.acl_table", controllerCriterion, cloneToCpuAction);

        //set Virtual Ip rule (10.0.0.1) - packet goes through load balancing if it has this IP
        PiCriterion myVirtualIpCriterion = PiCriterion.builder()
            .matchExact(
                PiMatchFieldId.of("hdr.ipv4.dst_addr"),
                loadBalancerConfig.myVirtualIp.toOctets())
            .build();
        PiTableAction noAction = PiAction.builder()
            .withId(PiActionId.of("NoAction"))
            .build();
        FlowRule myStationRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.my_virtual_ip_table", myVirtualIpCriterion, noAction);

        //ARP entry for Virtual Ip
        PiCriterion arpCriterion = PiCriterion.builder()
            .matchExact(
                PiMatchFieldId.of("hdr.arp.protoDstAddr"), 
                loadBalancerConfig.myVirtualIp.toOctets())
            .build();
        PiActionParam arpActionParam = new PiActionParam(
            PiActionParamId.of("target_mac"), 
            loadBalancerConfig.myVirtualMac.toBytes());
        PiAction arpAction = PiAction.builder()
            .withId(PiActionId.of("IngressPipeImpl.arp_request_to_reply"))
            .withParameter(arpActionParam)
            .build();
        FlowRule arpRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.arp_reply_table", arpCriterion, arpAction);

        //install all basic flow rules
        flowRuleService.applyFlowRules(aclRule, myStationRule, arpRule);

        //----
        //initial load balancing configuration for all online servers

        int count = (int) Math.ceil( 16 / loadBalancerConfig.servers.size() );
        int key = 0;
        for (String serverString : loadBalancerConfig.servers) {
            
            log.info("Adding {} entries to Load Balancing for {} ...", count, serverString);

            for ( int i = 0; i < count; i ++){
                
                //load_balancer_table
                String tableId2 = "IngressPipeImpl.load_balancer_table";

                PiCriterion match2 = PiCriterion.builder()
                        .matchExact(
                                PiMatchFieldId.of("local_metadata.next_server"),
                                key++ )
                        .build();

                List<PiActionParam> params = new LinkedList<PiActionParam>();
                params.add(new PiActionParam(
                    PiActionParamId.of("mac"),
                    MacAddress.valueOf(serverString.split("/")[0]).toBytes()));
                params.add(new PiActionParam(
                    PiActionParamId.of("ip"),
                    Ip4Address.valueOf(serverString.split("/")[1]).toOctets()));
                PiTableAction action2 = PiAction.builder()
                        .withId(PiActionId.of("IngressPipeImpl.set_next_server"))
                        .withParameters(params)
                        .build();
        
                FlowRule myStationRule2 = Utils.buildFlowRule(
                        deviceId, appId, tableId2, match2, action2);
        
                flowRuleService.applyFlowRules(myStationRule2);

            }

            //undo_server_table
            String tableId3 = "IngressPipeImpl.unset_server_table";

            PiCriterion match3 = PiCriterion.builder()
                    .matchExact(
                            PiMatchFieldId.of("hdr.ipv4.src_addr"),
                            Ip4Address.valueOf(serverString.split("/")[1]).toOctets() )
                    .build();

            List<PiActionParam> params = new LinkedList<PiActionParam>();
            params.add(new PiActionParam(
                PiActionParamId.of("mac"),
                loadBalancerConfig.myVirtualMac.toBytes()));
            params.add(new PiActionParam(
                PiActionParamId.of("ip"),
                loadBalancerConfig.myVirtualIp.toOctets()));
            PiTableAction action3 = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.unset_server"))
                    .withParameters(params)
                    .build();
    
            FlowRule myStationRule3 = Utils.buildFlowRule(
                    deviceId, appId, tableId3, match3, action3);
    
            flowRuleService.applyFlowRules(myStationRule3);
        }
    }

    //pre-load onlineServers with serverConfig string
    private void serverOnline(Host host){
        String hostName = host.annotations().value("name");
        DeviceId deviceId = host.location().deviceId();
        LoadBalancerConfig loadBalancerConfig = getLoadBalancerConfig(deviceId);
        String serverConfig = loadBalancerConfig.servers.stream()
            .filter(config -> config.split("/")[2].equals(hostName))
            .findFirst().get();
        onlineServers.put(hostName, serverConfig);
        log.info("Server online: {}", host);
    }

    //remove offline servers
    private void serverOffline(Host host){
        onlineServers.remove(host.annotations().value("name"));
        log.info("Server offline: {}", host);
    }

    //Install flow rules for servers
    class ServerLoad {
        public String server;
        public int load;
        public ServerLoad (String server, int load){
            this.server = server;
            this.load = load;
        }
    }

    public void InstallServerFlows(ServerLoad ... serverLoadArray){

    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of host events which triggers configuration of routing rules on
     * the device where the host is attached.
     */
    class InternalHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                case HOST_REMOVED:
                    break;
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts:
                    // how to support host moved/removed events?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(HostEvent event) {
            String hostName = event.subject().annotations().value("name");
            if (hostName.contains("server")){
                if (event.type() == Type.HOST_ADDED){
                    serverOnline(event.subject());
                } else if (event.type() == Type.HOST_REMOVED){
                    serverOffline(event.subject());
                }
            }
        }
    }

    class InternalLinkListener implements LinkListener {

        @Override
        public boolean isRelevant(LinkEvent event) {
            switch (event.type()) {
                case LINK_ADDED:
                    break;
                case LINK_UPDATED:
                case LINK_REMOVED:
                default:
                    return false;
            }
            DeviceId srcDev = event.subject().src().deviceId();
            DeviceId dstDev = event.subject().dst().deviceId();
            return mastershipService.isLocalMaster(srcDev) ||
                    mastershipService.isLocalMaster(dstDev);
        }

        @Override
        public void event(LinkEvent event) {

        }
    }

    /**
     * Listener of device events which triggers configuration of the My Station
     * table.
     */
    class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_AVAILABILITY_CHANGED:
                case DEVICE_ADDED:
                    break;
                default:
                    return false;
            }
            // Process device event if this controller instance is the master
            // for the device and the device is available.
            DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId) &&
                    deviceService.isAvailable(event.subject().id());
        }

        @Override
        public void event(DeviceEvent event) {
            mainComponent.getExecutorService().execute(() -> {
                DeviceId deviceId = event.subject().id();
                log.info("{} event! device id={}", event.type(), deviceId);
                setupLoadBalancer(deviceId);
            });
        }
    }

    class InternalPacketProcessor implements PacketProcessor {

        //cpu load algorithm
        public void processLoad(DeviceId deviceId, String[] serverLoadArray) {
            float load = Float.parseFloat(serverLoadArray[2]);
            serverLoadStorage.put(serverLoadArray[0], load);

            if(onlineServers.size() == 0){
                log.info("No servers online");
                return;
            } else {
                for (String srv : onlineServers.keySet()) {
                    if (!serverLoadStorage.containsKey(srv)){
                        log.info("serverLoadStorage incomplete");
                        return; //storage does not contain all servers yet
                    }
                }
            }
            float totalLoad = serverLoadStorage.values().stream().reduce((float)0, Float::sum);
            if (totalLoad < 1){
                log.info("Not enough load");
                serverLoadStorage.clear();
                return;
            }

            List<String> roundRobin = new LinkedList<String>();
            for (String srv : serverLoadStorage.keySet()){
                float srvLoad = serverLoadStorage.get(srv);

                int weigth = serverLoadStorage.size() == 1 ? 16 :
                    (int) Math.ceil( (1.0 - (srvLoad / totalLoad)) * 16.0);
                for (int j = 0; j < weigth; j++){
                    roundRobin.add(onlineServers.get(srv));
                }
                log.info("Added {} flows to {}", weigth, srv);
            }

            // DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            String tableId = "IngressPipeImpl.load_balancer_table";
            int k = 0;
            for (String srvConfig : roundRobin) {

                if (k >= 16) break;
                
                PiCriterion piCriterion = PiCriterion.builder()
                    .matchExact(
                        PiMatchFieldId.of("local_metadata.next_server"), 
                        k++ )
                    .build();
                
                // TODO change implementation to use 'range' key in P4
                
                List<PiActionParam> params = new LinkedList<PiActionParam>();
                params.add(new PiActionParam(
                    PiActionParamId.of("mac"), 
                    MacAddress.valueOf(srvConfig.split("/")[0]).toBytes()));
                params.add(new PiActionParam(
                    PiActionParamId.of("ip"),
                    Ip4Address.valueOf(srvConfig.split("/")[1]).toOctets()));
                PiTableAction piAction = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_next_server"))
                    .withParameters(params)
                    .build();
                
                FlowRule flowRule = Utils.buildFlowRule(
                    deviceId, appId, tableId, piCriterion, piAction);
                
                flowRuleService.applyFlowRules(flowRule);
            }
            
            //delete storage
            serverLoadStorage.clear();

        }

        //reponse time algorithm
        public void processTimer(DeviceId deviceId, String[] serverArray){

            //TODO basically the same as the cpu load distribution algorithm, but with the average time between cpu loads
        }


        @Override
        public void process (PacketContext context){
            // log.info("Packet received!");
            MacAddress mac = context.inPacket().parsed().getDestinationMAC();
            MacAddress lbMac = MacAddress.valueOf("00:aa:00:00:00:ff");
            if (mac.equals(lbMac)) {
                synchronized (serverLoadStorage){ //lock variable

                    ByteBuffer buffer = context.inPacket().unparsed().position(42); //body start position
                    byte[] body = new byte[64];
                    int i = 0;
                    while (buffer.hasRemaining()){
                        body[i++] = buffer.get();
                    }
                    String serverLoad = new String(body, StandardCharsets.UTF_8);
                    log.info("Server Load Packet: {}", serverLoad);
    
                    DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
                    String[] serverLoadArray = serverLoad.split(":");

                    if (serverLoadArray[1].equals("timer")){
                        processTimer(deviceId, serverLoadArray);
                        return;
                    } else if (serverLoadArray[1].equals("cpu")){
                        processLoad(deviceId, serverLoadArray);
                        return;
                    } else {
                        log.info("Invalid command: {}", serverLoad);
                    }

                }
            }
        }
    }


    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Returns the FabricDeviceConfig config object for the given device.
     *
     * @param deviceId the device ID
     * @return FabricDeviceConfig device config
     */
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(
                deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Returns the Load Balancer Config object
     * 
     * @param deviceId the device ID
     * @return LoadBalancerConfig load balancer config
     */
    private LoadBalancerConfig getLoadBalancerConfig(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::loadBalancerConfig)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing load balancer config for " + deviceId));
    }

    /**
     * Sets up IPv6 routing on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    log.info("*** Load Balancing - Starting initial set up for {}...", deviceId);
                    setupLoadBalancer(deviceId);
                    hostService.getConnectedHosts(deviceId).stream()
                        .filter(host -> host.annotations().value("name").contains("server"))
                        .forEach(host -> serverOnline(host));
                });
    }
}