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
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
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
import org.onosproject.ngsdn.tutorial.common.VxlanConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
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
public class VxlanComponent {

    private static final Logger log = LoggerFactory.getLogger(VxlanComponent.class);

    private static final int DEFAULT_ECMP_GROUP_ID = 0xec3b0000;
    private static final long GROUP_INSERT_DELAY_MILLIS = 200;

    private final HostListener hostListener = new InternalHostListener();
    private final LinkListener linkListener = new InternalLinkListener();
    private final DeviceListener deviceListener = new InternalDeviceListener();

    private ApplicationId appId;

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

        hostService.addListener(hostListener);
        linkService.addListener(linkListener);
        deviceService.addListener(deviceListener);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        linkService.removeListener(linkListener);
        deviceService.removeListener(deviceListener);

        log.info("Stopped");
    }


    private void setUpVxlan(DeviceId deviceId) {

        log.info("Adding VXLAN configurations to {} ...", deviceId);

        final List<VxlanConfig> vxlanConfigList = getDeviceConfig(deviceId).map(FabricDeviceConfig::vxlan)
            .orElseThrow(() -> new ItemNotFoundException(
                "Missing vxlan config for " + deviceId));
        
        for (VxlanConfig vxlanConfig : vxlanConfigList) {
            
            Ip4Prefix segmentPrefix = vxlanConfig.segment;
            int vni = vxlanConfig.vni;
            Ip4Address vtepIp = vxlanConfig.vtepIp;
            Ip4Address nexthop = vxlanConfig.nexthop;
            
            // FlowRule
            
            String segmentTable = "IngressPipeImpl.vxlan_segment_table";
            PiCriterion segmentMatch = PiCriterion.builder()
                    .matchLpm(
                        PiMatchFieldId.of("hdr.ipv4.dst_addr"),
                        segmentPrefix.address().toOctets(),
                        segmentPrefix.prefixLength())
                    .build();
            
            List<PiActionParam> params = new LinkedList<PiActionParam>();
            params.add(new PiActionParam(
                PiActionParamId.of("vni"),
                vni));
            params.add(new PiActionParam(
                PiActionParamId.of("vtep_ip"),
                vtepIp.toOctets()));
            params.add(new PiActionParam(
                PiActionParamId.of("nexthop"),
                nexthop.toOctets()));
            PiAction segmentAction = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_vxlan"))
                    .withParameters(params)
                    .build();
    
            flowRuleService.applyFlowRules(
                Utils.buildFlowRule( deviceId, appId, segmentTable, segmentMatch, segmentAction)
            );

            // Set own vtep
            PiCriterion vtepMatch = PiCriterion.builder()
                .matchExact(
                    PiMatchFieldId.of("hdr.ipv4.dst_addr"),
                    vtepIp.toOctets())
                .build();
            PiTableAction NoAction = PiAction.builder()
                .withId(PiActionId.of("NoAction"))
                .build();
            flowRuleService.applyFlowRules(
                Utils.buildFlowRule(deviceId, appId, "IngressPipeImpl.my_vtep", vtepMatch, NoAction)
            );
        }
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
                    break;
                case HOST_REMOVED:
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
            // Host host = event.subject();
            // DeviceId deviceId = host.location().deviceId();
            // mainComponent.getExecutorService().execute(() -> {
            //     log.info("{} event! host={}, deviceId={}, port={}",
            //             event.type(), host.id(), deviceId, host.location().port());
                

            // });
        }
    }

    /**
     * Listener of link events, which triggers configuration of routing rules to
     * forward packets across the fabric, i.e. from leaves to spines and vice
     * versa.
     * <p>
     * Reacting to link events instead of device ones, allows us to make sure
     * all device are always configured with a topology view that includes all
     * links, e.g. modifying an ECMP group as soon as a new link is added. The
     * downside is that we might be configuring the same device twice for the
     * same set of links/paths. However, the ONOS core treats these cases as a
     * no-op when the device is already configured with the desired forwarding
     * state (i.e. flows and groups)
     */
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
            // DeviceId srcDev = event.subject().src().deviceId();
            // DeviceId dstDev = event.subject().dst().deviceId();

            // if (mastershipService.isLocalMaster(srcDev)) {
            //     mainComponent.getExecutorService().execute(() -> {
            //         log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
            //                 event.type(), srcDev, srcDev, dstDev);

            //     });
            // }
            // if (mastershipService.isLocalMaster(dstDev)) {
            //     mainComponent.getExecutorService().execute(() -> {
            //         log.info("{} event! Configuring {}... linkSrc={}, linkDst={}",
            //                 event.type(), dstDev, srcDev, dstDev);

            //     });
            // }
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
                setUpVxlan(deviceId);
            });
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

    private List<VxlanConfig> getVxlanConfig(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::vxlan)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing vxlan config for " + deviceId));
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
                    log.info("*** IPV4 ROUTING - Starting initial set up for {}...", deviceId);
                    // setUpMyStationTable(deviceId);
                    // setUpGateway(deviceId);
                    // setUpFabricRoutes(deviceId);
                    // setUpL2NextHopRules(deviceId);
                    // hostService.getConnectedHosts(deviceId)
                    //         .forEach(host -> setUpHostRules(deviceId, host));
                    setUpVxlan(deviceId);
                });
    }
}
