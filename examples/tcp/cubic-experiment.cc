
/*
 * Copyright (c) 2013 ResiliNets, ITTC, University of Kansas
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Justin P. Rohrer, Truc Anh N. Nguyen, Siddharth Gangadhar
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group
 *
 * "TCP Westwood(+) Protocol Implementation in ns-3"
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/enum.h"
#include "ns3/error-model.h"
#include "ns3/event-id.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/tcp-header.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/traffic-control-module.h"
#include "ns3/udp-header.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpVariantsComparison");

static std::map<uint32_t, bool> firstCwnd;
static std::map<uint32_t, bool> firstSshThr;
static std::map<uint32_t, bool> firstRtt;
static std::map<uint32_t, bool> firstRto;

static std::map<uint32_t, Ptr<OutputStreamWrapper>> cWndStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> ssThreshStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rttStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rtoStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextTxStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextRxStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> inFlightStream;

static std::map<uint32_t, uint32_t> cWndValue;
static std::map<uint32_t, uint32_t> ssThreshValue;

/**
 * Extracts the node ID from a Config trace context.
 */
static uint32_t
GetNodeIdFromContext(std::string context)
{
    const std::size_t n1 = context.find_first_of('/', 1);
    const std::size_t n2 = context.find_first_of('/', n1 + 1);
    return std::stoul(context.substr(n1 + 1, n2 - n1 - 1));
}

static void
CwndTracer(std::string context, uint32_t oldval, uint32_t newval)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    if (firstCwnd[nodeId])
    {
        *cWndStream[nodeId]->GetStream() << "0.0 " << oldval << std::endl;
        firstCwnd[nodeId] = false;
    }

    *cWndStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << newval << std::endl;

    cWndValue[nodeId] = newval;
}

static void
SsThreshTracer(std::string context, uint32_t oldval, uint32_t newval)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    if (firstSshThr[nodeId])
    {
        *ssThreshStream[nodeId]->GetStream() << "0.0 " << oldval << std::endl;
        firstSshThr[nodeId] = false;
    }

    *ssThreshStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << newval << std::endl;

    ssThreshValue[nodeId] = newval;
}

static void
RttTracer(std::string context, Time oldval, Time newval)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    if (firstRtt[nodeId])
    {
        *rttStream[nodeId]->GetStream()
            << "0.0 " << oldval.GetSeconds() << std::endl;
        firstRtt[nodeId] = false;
    }

    *rttStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << newval.GetSeconds()
        << std::endl;
}

static void
RtoTracer(std::string context, Time oldval, Time newval)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    if (firstRto[nodeId])
    {
        *rtoStream[nodeId]->GetStream()
            << "0.0 " << oldval.GetSeconds() << std::endl;
        firstRto[nodeId] = false;
    }

    *rtoStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << newval.GetSeconds()
        << std::endl;
}

static void
NextTxTracer(std::string context,
             SequenceNumber32 old [[maybe_unused]],
             SequenceNumber32 nextTx)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    *nextTxStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << nextTx << std::endl;
}

static void
InFlightTracer(std::string context,
               uint32_t old [[maybe_unused]],
               uint32_t inFlight)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    *inFlightStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << inFlight << std::endl;
}

static void
NextRxTracer(std::string context,
             SequenceNumber32 old [[maybe_unused]],
             SequenceNumber32 nextRx)
{
    uint32_t nodeId = GetNodeIdFromContext(context);

    *nextRxStream[nodeId]->GetStream()
        << Simulator::Now().GetSeconds() << " " << nextRx << std::endl;
}

static void
TraceCwnd(std::string fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    cWndStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow",
                    MakeCallback(&CwndTracer));
}

static void
TraceSsThresh(std::string fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    ssThreshStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/SlowStartThreshold",
                    MakeCallback(&SsThreshTracer));
}

static void
TraceRtt(std::string fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    rttStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/RTT",
                    MakeCallback(&RttTracer));
}

static void
TraceRto(std::string fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    rtoStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/RTO",
                    MakeCallback(&RtoTracer));
}

static void
TraceNextTx(std::string& fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    nextTxStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/NextTxSequence",
                    MakeCallback(&NextTxTracer));
}

static void
TraceInFlight(std::string& fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    inFlightStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/BytesInFlight",
                    MakeCallback(&InFlightTracer));
}

static void
TraceNextRx(std::string& fileName, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    nextRxStream[nodeId] = ascii.CreateFileStream(fileName);

    Config::Connect("/NodeList/" + std::to_string(nodeId) +
                        "/$ns3::TcpL4Protocol/SocketList/0/RxBuffer/NextRxSequence",
                    MakeCallback(&NextRxTracer));
}

/**
 * Adds the ns3:: prefix when it is not already present.
 */
static std::string
NormalizeTypeName(const std::string& name)
{
    if (name.rfind("ns3::", 0) == 0)
    {
        return name;
    }

    return "ns3::" + name;
}

int
main(int argc, char* argv[])
{
    // ------------------------------------------------------------
    // Experiment parameters
    // ------------------------------------------------------------

    std::string transport_prot = "TcpCubic";
    double error_p = 0.0;

    std::string bandwidth = "2Mbps";
    std::string delay = "0.01ms";

    std::string access_bandwidth = "10Mbps";
    std::string access_delay = "45ms";
    std::string access_delays = "";

    bool tracing = false;

    std::string prefix_file_name = "CubicExperiment";
    std::string results_dir = "../../results";

    uint64_t data_mbytes = 0;
    uint32_t mtu_bytes = 400;
    uint16_t num_flows = 4;

    // Measurement duration excludes warm-up.
    double duration = 300.0;
    double warmup = 20.0;

    // Random flow start offsets.
    double random_start_max = 2.0;

    // Bottleneck queue size in multiples of BDP.
    double queue_bdp = 1.0;

    // Optional per-flow TCP algorithms.
    std::string flow_algorithms = "";

    uint32_t run = 1;

    bool flow_monitor = false;
    bool pcap = false;
    bool sack = true;

    std::string queue_disc_type = "ns3::PfifoFastQueueDisc";
    std::string recovery = "ns3::TcpClassicRecovery";

    // ------------------------------------------------------------
    // Command-line options
    // ------------------------------------------------------------

    CommandLine cmd(__FILE__);

    cmd.AddValue("transport_prot",
                 "Default TCP protocol for all flows",
                 transport_prot);

    cmd.AddValue("error_p", "Packet error rate", error_p);

    cmd.AddValue("bandwidth", "Bottleneck bandwidth", bandwidth);
    cmd.AddValue("delay", "Bottleneck one-way delay", delay);

    cmd.AddValue("access_bandwidth", "Access link bandwidth", access_bandwidth);
    cmd.AddValue("access_delay", "Default access link one-way delay", access_delay);

    cmd.AddValue("access_delays",
                 "Comma-separated access delays, one per flow",
                 access_delays);

    cmd.AddValue("tracing", "Enable or disable tracing", tracing);
    cmd.AddValue("prefix_name", "Prefix of output trace files", prefix_file_name);
    cmd.AddValue("results_dir", "Directory for output results", results_dir);

    cmd.AddValue("data", "Number of megabytes to transmit", data_mbytes);
    cmd.AddValue("mtu", "IP packet size in bytes", mtu_bytes);
    cmd.AddValue("num_flows", "Number of TCP flows", num_flows);

    cmd.AddValue("duration",
                 "Measurement duration in seconds, excluding warm-up",
                 duration);

    cmd.AddValue("warmup",
                 "Warm-up period in seconds, excluded from FlowMonitor",
                 warmup);

    cmd.AddValue("random_start_max",
                 "Maximum random start offset for each flow in seconds",
                 random_start_max);

    cmd.AddValue("queue_bdp",
                 "Bottleneck queue size as a multiple of BDP",
                 queue_bdp);

    cmd.AddValue("flow_algorithms",
                 "Optional comma-separated TCP algorithm for each flow",
                 flow_algorithms);

    cmd.AddValue("run", "Random run index", run);

    cmd.AddValue("flow_monitor", "Enable FlowMonitor", flow_monitor);
    cmd.AddValue("pcap_tracing", "Enable PCAP tracing", pcap);

    cmd.AddValue("queue_disc_type",
                 "Bottleneck queue discipline: ns3::PfifoFastQueueDisc or ns3::CoDelQueueDisc",
                 queue_disc_type);

    cmd.AddValue("sack", "Enable or disable TCP SACK", sack);

    cmd.AddValue("recovery",
                 "TCP recovery algorithm",
                 recovery);

    cmd.Parse(argc, argv);

    // ------------------------------------------------------------
    // Validate parameters
    // ------------------------------------------------------------

    NS_ABORT_MSG_IF(num_flows == 0, "num_flows must be greater than zero");
    NS_ABORT_MSG_IF(duration <= 0.0, "duration must be positive");
    NS_ABORT_MSG_IF(warmup < 0.0, "warmup cannot be negative");
    NS_ABORT_MSG_IF(random_start_max < 0.0,
                    "random_start_max cannot be negative");
    NS_ABORT_MSG_IF(queue_bdp <= 0.0, "queue_bdp must be positive");
    NS_ABORT_MSG_IF(error_p < 0.0 || error_p > 1.0,
                    "error_p must be between 0 and 1");

    NS_ABORT_MSG_IF(mtu_bytes <= 60,
                    "mtu must be greater than 60 bytes");

    NS_ABORT_MSG_IF(queue_disc_type != "ns3::PfifoFastQueueDisc" &&
                        queue_disc_type != "ns3::CoDelQueueDisc",
                    "Unsupported queue discipline: " << queue_disc_type);

    const double measurement_start = warmup;
    const double measurement_stop = warmup + duration;

    // Extra time allows packets and ACKs to drain after measurement.
    const double simulation_stop = measurement_stop + 5.0;

    const std::string output_prefix =
        results_dir + "/" + prefix_file_name;

    // ------------------------------------------------------------
    // Parse per-flow access delays
    // ------------------------------------------------------------

    std::vector<std::string> flow_access_delays;

    if (access_delays.empty())
    {
        flow_access_delays.assign(num_flows, access_delay);
    }
    else
    {
        std::stringstream ss(access_delays);
        std::string item;

        while (std::getline(ss, item, ','))
        {
            NS_ABORT_MSG_IF(item.empty(),
                            "Empty value in access_delays");

            flow_access_delays.push_back(item);
        }

        NS_ABORT_MSG_IF(flow_access_delays.size() != num_flows,
                        "access_delays must contain exactly "
                            << num_flows << " values");
    }

    // ------------------------------------------------------------
    // Parse per-flow TCP algorithms
    // ------------------------------------------------------------

    std::vector<std::string> flow_tcp_types;

    if (flow_algorithms.empty())
    {
        flow_tcp_types.assign(num_flows, transport_prot);
    }
    else
    {
        std::stringstream ss(flow_algorithms);
        std::string item;

        while (std::getline(ss, item, ','))
        {
            NS_ABORT_MSG_IF(item.empty(),
                            "Empty value in flow_algorithms");

            flow_tcp_types.push_back(item);
        }

        NS_ABORT_MSG_IF(flow_tcp_types.size() != num_flows,
                        "flow_algorithms must contain exactly "
                            << num_flows << " values");
    }

    for (auto& algorithm : flow_tcp_types)
    {
        algorithm = NormalizeTypeName(algorithm);

        TypeId algorithmType;

        NS_ABORT_MSG_UNLESS(
            TypeId::LookupByNameFailSafe(algorithm, &algorithmType),
            "Unknown TCP algorithm: " << algorithm);
    }

    transport_prot = NormalizeTypeName(transport_prot);

    TypeId defaultTcpType;

    NS_ABORT_MSG_UNLESS(
        TypeId::LookupByNameFailSafe(transport_prot, &defaultTcpType),
        "TCP TypeId not found: " << transport_prot);

    TypeId recoveryType;

    NS_ABORT_MSG_UNLESS(
        TypeId::LookupByNameFailSafe(recovery, &recoveryType),
        "Recovery TypeId not found: " << recovery);

    // ------------------------------------------------------------
    // Reproducible randomization
    // ------------------------------------------------------------

    SeedManager::SetSeed(1);
    SeedManager::SetRun(run);

    /*
     * Stream 100 is reserved for flow start times.
     *
     * The same run index generates the same start offsets,
     * allowing paired comparisons between TCP algorithms.
     */
    Ptr<UniformRandomVariable> startRandom =
        CreateObject<UniformRandomVariable>();

    startRandom->SetStream(100);

    std::vector<double> flow_start_times;

    for (uint32_t i = 0; i < num_flows; ++i)
    {
        const double start =
            startRandom->GetValue(0.0, random_start_max);

        flow_start_times.push_back(start);

        NS_LOG_UNCOND("Flow " << i
                              << " start offset: "
                              << start << " seconds");
    }

    // ------------------------------------------------------------
    // TCP configuration
    // ------------------------------------------------------------

    Config::SetDefault("ns3::TcpSocket::RcvBufSize",
                       UintegerValue(1 << 21));

    Config::SetDefault("ns3::TcpSocket::SndBufSize",
                       UintegerValue(1 << 21));

    Config::SetDefault("ns3::TcpSocketBase::Sack",
                       BooleanValue(sack));

    Config::SetDefault("ns3::TcpL4Protocol::RecoveryType",
                       TypeIdValue(recoveryType));

    // Default TCP algorithm. Per-node overrides are applied below.
    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       TypeIdValue(defaultTcpType));

    // ------------------------------------------------------------
    // Calculate TCP application data unit
    // ------------------------------------------------------------

    Header* temp_header = new Ipv4Header();
    const uint32_t ip_header = temp_header->GetSerializedSize();
    delete temp_header;

    temp_header = new TcpHeader();
    const uint32_t tcp_header = temp_header->GetSerializedSize();
    delete temp_header;

    const uint32_t tcp_adu_size =
        mtu_bytes - 20 - (ip_header + tcp_header);

    NS_ABORT_MSG_IF(tcp_adu_size == 0,
                    "Calculated TCP application data unit is zero");

    // ------------------------------------------------------------
    // Create nodes
    // ------------------------------------------------------------

    NodeContainer gateways;
    gateways.Create(2);

    NodeContainer sources;
    sources.Create(num_flows);

    NodeContainer sinks;
    sinks.Create(num_flows);

    // ------------------------------------------------------------
    // Configure packet error model
    // ------------------------------------------------------------

    Ptr<UniformRandomVariable> errorRandom =
        CreateObject<UniformRandomVariable>();

    errorRandom->SetStream(50);

    Ptr<RateErrorModel> errorModel =
        CreateObject<RateErrorModel>();

    errorModel->SetRandomVariable(errorRandom);
    errorModel->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
    errorModel->SetRate(error_p);

    // ------------------------------------------------------------
    // Install Internet stack
    // ------------------------------------------------------------

    InternetStackHelper stack;
    stack.InstallAll();

    /*
     * Each source node receives its own TCP implementation.
     * This allows mixed CUBIC/CUBIC-RTT coexistence experiments.
     */
    for (uint32_t i = 0; i < num_flows; ++i)
    {
        Ptr<TcpL4Protocol> tcp =
            sources.Get(i)->GetObject<TcpL4Protocol>();

        NS_ABORT_MSG_IF(tcp == nullptr,
                        "TcpL4Protocol not found on source node "
                            << i);

        TypeId algorithmType =
            TypeId::LookupByName(flow_tcp_types[i]);

        tcp->SetAttribute("SocketType",
                          TypeIdValue(algorithmType));
    }

    // ------------------------------------------------------------
    // Configure link helpers
    // ------------------------------------------------------------

    PointToPointHelper bottleneckLink;

    bottleneckLink.SetDeviceAttribute(
        "DataRate",
        StringValue(bandwidth));

    bottleneckLink.SetChannelAttribute(
        "Delay",
        StringValue(delay));

    bottleneckLink.SetDeviceAttribute(
        "ReceiveErrorModel",
        PointerValue(errorModel));

    PointToPointHelper accessLink;

    accessLink.SetDeviceAttribute(
        "DataRate",
        StringValue(access_bandwidth));

    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");

    // ------------------------------------------------------------
    // Calculate the reference RTT and bottleneck BDP
    // ------------------------------------------------------------

    DataRate bottleneckRate(bandwidth);

    Time maxAccessDelay = Seconds(0);

    for (const auto& flowDelay : flow_access_delays)
    {
        Time currentDelay(flowDelay);

        if (currentDelay > maxAccessDelay)
        {
            maxAccessDelay = currentDelay;
        }
    }

    const Time bottleneckDelay(delay);

    /*
     * Reference RTT uses the longest access delay:
     *
     * RTT = 2 * (access delay + bottleneck delay + access delay)
     *
     * This is a reference queue-sizing value for the heterogeneous
     * topology. Individual flows can have smaller RTTs.
     */
    const double referenceRttSeconds =
        2.0 * (2.0 * maxAccessDelay.GetSeconds() +
               bottleneckDelay.GetSeconds());

    const double bdpBytes =
        static_cast<double>(bottleneckRate.GetBitRate()) *
        referenceRttSeconds / 8.0;

    const uint64_t bottleneckQueueBytes =
        static_cast<uint64_t>(
            std::ceil(bdpBytes * queue_bdp));

    const uint32_t bottleneckQueuePackets =
        static_cast<uint32_t>(
            std::max<uint64_t>(
                1,
                (bottleneckQueueBytes + mtu_bytes - 1) /
                    mtu_bytes));

    NS_LOG_UNCOND("Reference RTT: "
                  << referenceRttSeconds << " seconds");

    NS_LOG_UNCOND("Bottleneck BDP: "
                  << bdpBytes << " bytes");

    NS_LOG_UNCOND("Bottleneck queue: "
                  << bottleneckQueueBytes << " bytes ("
                  << bottleneckQueuePackets << " packets)");

    // ------------------------------------------------------------
    // Configure access-link queues separately
    // ------------------------------------------------------------

    /*
     * Access queues are deliberately independent from the
     * bottleneck BDP queue.
     *
     * The access links use a fixed generous limit so that the
     * experimental bottleneck remains the principal congestion point.
     */
    Config::SetDefault(
        "ns3::PfifoFastQueueDisc::MaxSize",
        QueueSizeValue(
            QueueSize(QueueSizeUnit::PACKETS, 1000)));

    Config::SetDefault(
        "ns3::CoDelQueueDisc::MaxSize",
        QueueSizeValue(
            QueueSize(QueueSizeUnit::BYTES, 1000000)));

    TrafficControlHelper accessQueue;
    accessQueue.SetRootQueueDisc("ns3::PfifoFastQueueDisc");

    // ------------------------------------------------------------
    // Source -> Gateway A
    // ------------------------------------------------------------

    for (uint32_t i = 0; i < num_flows; ++i)
    {
        accessLink.SetChannelAttribute(
            "Delay",
            StringValue(flow_access_delays[i]));

        NetDeviceContainer devices =
            accessLink.Install(sources.Get(i), gateways.Get(0));

        accessQueue.Install(devices);

        address.NewNetwork();
        address.Assign(devices);
    }

    // ------------------------------------------------------------
    // Gateway A -> Gateway B (bottleneck)
    // ------------------------------------------------------------

    /*
     * Set the bottleneck queue size immediately before installing
     * the bottleneck queue discipline.
     */
    if (queue_disc_type == "ns3::PfifoFastQueueDisc")
    {
        Config::SetDefault(
            "ns3::PfifoFastQueueDisc::MaxSize",
            QueueSizeValue(
                QueueSize(QueueSizeUnit::PACKETS,
                          bottleneckQueuePackets)));
    }
    else if (queue_disc_type == "ns3::CoDelQueueDisc")
    {
        Config::SetDefault(
            "ns3::CoDelQueueDisc::MaxSize",
            QueueSizeValue(
                QueueSize(QueueSizeUnit::BYTES,
                          bottleneckQueueBytes)));
    }

    NetDeviceContainer bottleneckDevices =
        bottleneckLink.Install(gateways.Get(0), gateways.Get(1));

    TrafficControlHelper bottleneckQueue;
    bottleneckQueue.SetRootQueueDisc(queue_disc_type);
    bottleneckQueue.Install(bottleneckDevices);

    address.NewNetwork();
    address.Assign(bottleneckDevices);

    // ------------------------------------------------------------
    // Gateway B -> Sink
    // ------------------------------------------------------------

    Ipv4InterfaceContainer sink_interfaces;

    for (uint32_t i = 0; i < num_flows; ++i)
    {
        accessLink.SetChannelAttribute(
            "Delay",
            StringValue(flow_access_delays[i]));

        NetDeviceContainer devices =
            accessLink.Install(gateways.Get(1), sinks.Get(i));

        accessQueue.Install(devices);

        address.NewNetwork();

        Ipv4InterfaceContainer interfaces =
            address.Assign(devices);

        sink_interfaces.Add(interfaces.Get(1));
    }

    // ------------------------------------------------------------
    // Routing
    // ------------------------------------------------------------

    NS_LOG_INFO("Initialize Global Routing.");

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ------------------------------------------------------------
    // Applications
    // ------------------------------------------------------------

    const uint16_t port = 50000;

    Address sinkLocalAddress(
        InetSocketAddress(Ipv4Address::GetAny(), port));

    PacketSinkHelper sinkHelper(
        "ns3::TcpSocketFactory",
        sinkLocalAddress);

    for (uint32_t i = 0; i < num_flows; ++i)
    {
        AddressValue remoteAddress(
            InetSocketAddress(sink_interfaces.GetAddress(i), port));

        Config::SetDefault(
            "ns3::TcpSocket::SegmentSize",
            UintegerValue(tcp_adu_size));

        BulkSendHelper sourceHelper(
            "ns3::TcpSocketFactory",
            Address());

        sourceHelper.SetAttribute("Remote", remoteAddress);

        sourceHelper.SetAttribute(
            "SendSize",
            UintegerValue(tcp_adu_size));

        sourceHelper.SetAttribute(
            "MaxBytes",
            UintegerValue(data_mbytes * 1000000));

        ApplicationContainer sourceApp =
            sourceHelper.Install(sources.Get(i));

        /*
         * Flows begin at reproducible randomized offsets.
         * The measurement window starts after warm-up.
         */
        sourceApp.Start(Seconds(flow_start_times[i]));

        sourceApp.Stop(Seconds(measurement_stop));

        ApplicationContainer sinkApp =
            sinkHelper.Install(sinks.Get(i));

        sinkApp.Start(Seconds(0.0));
        sinkApp.Stop(Seconds(simulation_stop));
    }

    // ------------------------------------------------------------
    // Tracing
    // ------------------------------------------------------------

    if (tracing)
    {
        Ptr<OutputStreamWrapper> ascii_wrap =
            Create<OutputStreamWrapper>(
                output_prefix + "-ascii",
                std::ios::out);

        stack.EnableAsciiIpv4All(ascii_wrap);

        for (uint16_t index = 0; index < num_flows; ++index)
        {
            std::string flowString;

            if (num_flows > 1)
            {
                flowString =
                    "-flow" + std::to_string(index);
            }

            // Gateway nodes are 0 and 1.
            const uint32_t sourceNodeId = index + 2;

            // Sink nodes follow the gateways and source nodes.
            const uint32_t sinkNodeId =
                num_flows + index + 2;

            firstCwnd[sourceNodeId] = true;
            firstSshThr[sourceNodeId] = true;
            firstRtt[sourceNodeId] = true;
            firstRto[sourceNodeId] = true;

            const double traceStart =
                flow_start_times[index] + 0.00001;

            Simulator::Schedule(
                Seconds(traceStart),
                &TraceCwnd,
                output_prefix + flowString + "-cwnd.data",
                sourceNodeId);

            Simulator::Schedule(
                Seconds(traceStart),
                &TraceSsThresh,
                output_prefix + flowString + "-ssth.data",
                sourceNodeId);

            Simulator::Schedule(
                Seconds(traceStart),
                &TraceRtt,
                output_prefix + flowString + "-rtt.data",
                sourceNodeId);

            Simulator::Schedule(
                Seconds(traceStart),
                &TraceRto,
                output_prefix + flowString + "-rto.data",
                sourceNodeId);

            Simulator::Schedule(
                Seconds(traceStart),
                &TraceNextTx,
                output_prefix + flowString + "-next-tx.data",
                sourceNodeId);

            Simulator::Schedule(
                Seconds(traceStart),
                &TraceInFlight,
                output_prefix + flowString + "-inflight.data",
                sourceNodeId);

            Simulator::Schedule(
                Seconds(flow_start_times[index] + 0.1),
                &TraceNextRx,
                output_prefix + flowString + "-next-rx.data",
                sinkNodeId);
        }
    }

    // ------------------------------------------------------------
    // PCAP
    // ------------------------------------------------------------

    if (pcap)
    {
        bottleneckLink.EnablePcapAll(output_prefix, true);
        accessLink.EnablePcapAll(output_prefix, true);
    }

    // ------------------------------------------------------------
    // FlowMonitor
    // ------------------------------------------------------------

    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor;

    if (flow_monitor)
    {
        monitor = flowHelper.InstallAll();
        monitor->SetHistogramsEnabled(false);
        monitor->SetProbeStatsEnabled(false);

        /*
         * Ignore the warm-up period and collect statistics only
         * during the configured measurement interval.
         */
        monitor->Start(Seconds(measurement_start));
        monitor->Stop(Seconds(measurement_stop));
    }

    // ------------------------------------------------------------
    // Run simulation
    // ------------------------------------------------------------

    Simulator::Stop(Seconds(simulation_stop));

    Simulator::Run();

    // ------------------------------------------------------------
    // Save FlowMonitor results
    // ------------------------------------------------------------

    if (flow_monitor)
    {
        monitor->CheckForLostPackets();

        monitor->SerializeToXmlFile(
            output_prefix + ".flowmonitor",
            false,
            false);
    }

    Simulator::Destroy();

    return 0;
}