/*
 * Copyright (c) 2014 Natale Patriciello <natale.patriciello@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define NS_LOG_APPEND_CONTEXT                                                                      \
    {                                                                                              \
        std::clog << Simulator::Now().GetSeconds() << " ";                                         \
    }

#include "tcp-cubic-rtt.h"
#include <algorithm>
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE("TcpCubicRtt");

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(TcpCubicRtt);

TypeId
TcpCubicRtt::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::TcpCubicRtt")
            .SetParent<TcpCongestionOps>()
            .AddConstructor<TcpCubicRtt>()
            .SetGroupName("Internet")
            .AddAttribute("FastConvergence",
                          "Enable (true) or disable (false) fast convergence",
                          BooleanValue(true),
                          MakeBooleanAccessor(&TcpCubicRtt::m_fastConvergence),
                          MakeBooleanChecker())
            .AddAttribute("TcpFriendliness",
                          "Enable (true) or disable (false) TCP friendliness",
                          BooleanValue(true),
                          MakeBooleanAccessor(&TcpCubicRtt::m_tcpFriendliness),
                          MakeBooleanChecker())
            .AddAttribute("Beta",
                          "Beta for multiplicative decrease",
                          DoubleValue(0.7),
                          MakeDoubleAccessor(&TcpCubicRtt::m_beta),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("BetaEcn",
                          "Beta for multiplicative decrease for ABE",
                          DoubleValue(0.85), // According to RFC 8511 (ABE)
                          MakeDoubleAccessor(&TcpCubicRtt::m_betaEcn),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("HyStart",
                          "Enable (true) or disable (false) hybrid slow start algorithm",
                          BooleanValue(true),
                          MakeBooleanAccessor(&TcpCubicRtt::m_hystart),
                          MakeBooleanChecker())
            .AddAttribute("HyStartLowWindow",
                          "Lower bound cWnd for hybrid slow start (segments)",
                          UintegerValue(16),
                          MakeUintegerAccessor(&TcpCubicRtt::m_hystartLowWindow),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("HyStartDetect",
                          "Hybrid Slow Start detection mechanisms:"
                          "packet train, delay, both",
                          EnumValue(HybridSSDetectionMode::BOTH),
                          MakeEnumAccessor<HybridSSDetectionMode>(&TcpCubicRtt::m_hystartDetect),
                          MakeEnumChecker(HybridSSDetectionMode::PACKET_TRAIN,
                                          "PACKET_TRAIN",
                                          HybridSSDetectionMode::DELAY,
                                          "DELAY",
                                          HybridSSDetectionMode::BOTH,
                                          "BOTH"))
            .AddAttribute("HyStartMinSamples",
                          "Number of delay samples for detecting the increase of delay",
                          UintegerValue(8),
                          MakeUintegerAccessor(&TcpCubicRtt::m_hystartMinSamples),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("HyStartAckDelta",
                          "Spacing between ack's indicating train",
                          TimeValue(MilliSeconds(2)),
                          MakeTimeAccessor(&TcpCubicRtt::m_hystartAckDelta),
                          MakeTimeChecker())
            .AddAttribute("HyStartDelayMin",
                          "Minimum time for hystart algorithm",
                          TimeValue(MilliSeconds(4)),
                          MakeTimeAccessor(&TcpCubicRtt::m_hystartDelayMin),
                          MakeTimeChecker())
            .AddAttribute("HyStartDelayMax",
                          "Maximum time for hystart algorithm",
                          TimeValue(MilliSeconds(1000)),
                          MakeTimeAccessor(&TcpCubicRtt::m_hystartDelayMax),
                          MakeTimeChecker())
            .AddAttribute("CubicDelta",
                          "Delta Time to wait after fast recovery before adjusting param",
                          TimeValue(MilliSeconds(10)),
                          MakeTimeAccessor(&TcpCubicRtt::m_cubicDelta),
                          MakeTimeChecker())
            .AddAttribute("CntClamp",
                          "Counter value when no losses are detected (counter is used"
                          " when incrementing cWnd in congestion avoidance, to avoid"
                          " floating point arithmetic). It is the modulo of the (avoided)"
                          " division",
                          UintegerValue(20),
                          MakeUintegerAccessor(&TcpCubicRtt::m_cntClamp),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("C",
                          "Cubic Scaling factor",
                          DoubleValue(0.4),
                          MakeDoubleAccessor(&TcpCubicRtt::m_c),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("RttReference",
                          "Reference RTT for adaptive adjustment",
                          TimeValue(MilliSeconds(200)),
                          MakeTimeAccessor(&TcpCubicRtt::m_rttReference),
                          MakeTimeChecker(NanoSeconds(1)))
            .AddAttribute("Alpha",
                          "Intensity of RTT-based C adjustment",
                          DoubleValue(0.25),
                          MakeDoubleAccessor(&TcpCubicRtt::m_alpha),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("Gamma",
                          "Intensity of RTT-based Beta adjustment",
                          DoubleValue(0.05),
                          MakeDoubleAccessor(&TcpCubicRtt::m_gamma),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("BetaMin",
                          "Minimum adaptive Beta",
                          DoubleValue(0.65),
                          MakeDoubleAccessor(&TcpCubicRtt::m_betaMin),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("BetaMax",
                          "Maximum adaptive Beta",
                          DoubleValue(0.85),
                          MakeDoubleAccessor(&TcpCubicRtt::m_betaMax),
                          MakeDoubleChecker<double>(0.0, 1.0));
    return tid;
}

TcpCubicRtt::TcpCubicRtt()
    : TcpCongestionOps(),
      m_cEpoch(0.0),
      m_cWndCnt(0),
      m_lastMaxCwnd(0),
      m_bicOriginPoint(0),
      m_bicK(0.0),
      m_delayMin(Time::Min()),
      m_epochStart(Time::Min()),
      m_found(false),
      m_roundStart(Time::Min()),
      m_endSeq(0),
      m_lastAck(Time::Min()),
      m_cubicDelta(Time::Min()),
      m_currRtt(Time::Min()),
      m_sampleCnt(0)
{
    NS_LOG_FUNCTION(this);
}

TcpCubicRtt::TcpCubicRtt(const TcpCubicRtt& sock)
    : TcpCongestionOps(sock),
      m_fastConvergence(sock.m_fastConvergence),
      m_tcpFriendliness(sock.m_tcpFriendliness),
      m_beta(sock.m_beta),
      m_betaEcn(sock.m_betaEcn),
      m_hystart(sock.m_hystart),
      m_hystartDetect(sock.m_hystartDetect),
      m_hystartLowWindow(sock.m_hystartLowWindow),
      m_hystartAckDelta(sock.m_hystartAckDelta),
      m_hystartDelayMin(sock.m_hystartDelayMin),
      m_hystartDelayMax(sock.m_hystartDelayMax),
      m_hystartMinSamples(sock.m_hystartMinSamples),
      m_initialCwnd(sock.m_initialCwnd),
      m_cntClamp(sock.m_cntClamp),
      m_c(sock.m_c),
      m_rttReference(sock.m_rttReference),
      m_alpha(sock.m_alpha),
      m_gamma(sock.m_gamma),
      m_betaMin(sock.m_betaMin),
      m_betaMax(sock.m_betaMax),
      m_cEpoch(sock.m_cEpoch),
      m_cWndCnt(sock.m_cWndCnt),
      m_lastMaxCwnd(sock.m_lastMaxCwnd),
      m_bicOriginPoint(sock.m_bicOriginPoint),
      m_bicK(sock.m_bicK),
      m_delayMin(sock.m_delayMin),
      m_epochStart(sock.m_epochStart),
      m_found(sock.m_found),
      m_roundStart(sock.m_roundStart),
      m_endSeq(sock.m_endSeq),
      m_lastAck(sock.m_lastAck),
      m_cubicDelta(sock.m_cubicDelta),
      m_currRtt(sock.m_currRtt),
      m_sampleCnt(sock.m_sampleCnt),
      m_ackCnt(sock.m_ackCnt),
      m_tcpCwnd(sock.m_tcpCwnd)
{
    NS_LOG_FUNCTION(this);
}

std::string
TcpCubicRtt::GetName() const
{
    return "TcpCubicRtt";
}

void
TcpCubicRtt::Init(Ptr<TcpSocketState> tcb)
{
    HystartReset(tcb);
}

void
TcpCubicRtt::HystartReset(Ptr<const TcpSocketState> tcb)
{
    NS_LOG_FUNCTION(this);

    m_roundStart = m_lastAck = Simulator::Now();
    m_endSeq = tcb->m_highTxMark;
    m_currRtt = Time::Min();
    m_sampleCnt = 0;
}

void
TcpCubicRtt::IncreaseWindow(Ptr<TcpSocketState> tcb, uint32_t segmentsAcked)
{
    NS_LOG_FUNCTION(this << tcb << segmentsAcked);

    if (!tcb->m_isCwndLimited)
    {
        NS_LOG_DEBUG("No increase because current cwnd " << tcb->m_cWnd
                                                         << " is not limiting the flow");
        return;
    }

    if (tcb->m_cWnd < tcb->m_ssThresh)
    {
        if (m_hystart && tcb->m_lastAckedSeq > m_endSeq)
        {
            HystartReset(tcb);
        }

        // In Linux, the QUICKACK socket option enables the receiver to send
        // immediate acks initially (during slow start) and then transition
        // to delayed acks.  ns-3 does not implement QUICKACK, and if ack
        // counting instead of byte counting is used during slow start window
        // growth, when TcpSocket::DelAckCount==2, then the slow start will
        // not reach as large of an initial window as in Linux.  Therefore,
        // we can approximate the effect of QUICKACK by making this slow
        // start phase perform Appropriate Byte Counting (RFC 3465)
        tcb->m_cWnd += segmentsAcked * tcb->m_segmentSize;
        segmentsAcked = 0;

        NS_LOG_INFO("In SlowStart, updated to cwnd " << tcb->m_cWnd << " ssthresh "
                                                     << tcb->m_ssThresh);
    }

    if (tcb->m_cWnd >= tcb->m_ssThresh && segmentsAcked > 0)
    {
        m_cWndCnt += segmentsAcked;
        uint32_t cnt = Update(tcb, segmentsAcked);

        /* According to RFC 6356 even once the new cwnd is
         * calculated you must compare this to the number of ACKs received since
         * the last cwnd update. If not enough ACKs have been received then cwnd
         * cannot be updated.
         */
        if (m_cWndCnt >= cnt)
        {
            tcb->m_cWnd += tcb->m_segmentSize;
            m_cWndCnt -= cnt;
            NS_LOG_INFO("In CongAvoid, updated to cwnd " << tcb->m_cWnd);
        }
        else
        {
            NS_LOG_INFO("Not enough segments have been ACKed to increment cwnd."
                        "Until now "
                        << m_cWndCnt << " cnd " << cnt);
        }
    }
}

uint32_t
TcpCubicRtt::Update(Ptr<TcpSocketState> tcb, uint32_t segmentsAcked)
{
    NS_LOG_FUNCTION(this);
    Time t;
    uint32_t delta;
    uint32_t bicTarget;
    uint32_t cnt = 0;
    uint32_t maxCnt;
    double offs;
    uint32_t segCwnd = tcb->GetCwndInSegments();

    m_ackCnt += segmentsAcked;

    if (m_epochStart == Time::Min())
    {
        m_cEpoch = CalculateAdaptiveC();
        NS_LOG_DEBUG("CUBIC-RTT: New epoch"
             << " | RTT min = " << m_delayMin.GetMilliSeconds() << " ms"
             << " | RTT reference = " << m_rttReference.GetMilliSeconds() << " ms"
             << " | C adaptive = " << m_cEpoch);
        m_epochStart = Simulator::Now(); // record the beginning of an epoch
        m_ackCnt = segmentsAcked;
        m_tcpCwnd = segCwnd;

        if (m_lastMaxCwnd <= segCwnd)
        {
            NS_LOG_DEBUG("lastMaxCwnd <= m_cWnd. K=0 and origin=" << segCwnd);
            m_bicK = 0.0;
            m_bicOriginPoint = segCwnd;
        }
        else
        {
            m_bicK = std::pow((m_lastMaxCwnd - segCwnd) / m_cEpoch, 1 / 3.);
            m_bicOriginPoint = m_lastMaxCwnd;
            NS_LOG_DEBUG("lastMaxCwnd > m_cWnd. K=" << m_bicK << " and origin=" << m_lastMaxCwnd);
        }
    }

    t = Simulator::Now() + m_delayMin - m_epochStart;

    if (t.GetSeconds() < m_bicK) /* t - K */
    {
        offs = m_bicK - t.GetSeconds();
        NS_LOG_DEBUG("t=" << t.GetSeconds() << " <k: offs=" << offs);
    }
    else
    {
        offs = t.GetSeconds() - m_bicK;
        NS_LOG_DEBUG("t=" << t.GetSeconds() << " >= k: offs=" << offs);
    }

    /* Constant value taken from Experimental Evaluation of Cubic Tcp, available at
     * eprints.nuim.ie/1716/1/Hamiltonpfldnet2007_cubic_final.pdf */
    delta = m_cEpoch * std::pow(offs, 3);

    NS_LOG_DEBUG("delta: " << delta);

    if (t.GetSeconds() < m_bicK)
    {
        // below origin
        bicTarget = m_bicOriginPoint - delta;
        NS_LOG_DEBUG("t < k: Bic Target: " << bicTarget);
    }
    else
    {
        // above origin
        bicTarget = m_bicOriginPoint + delta;
        NS_LOG_DEBUG("t >= k: Bic Target: " << bicTarget);
    }

    // Next the window target is converted into a cnt or count value. CUBIC will
    // wait until enough new ACKs have arrived that a counter meets or exceeds
    // this cnt value. This is how the CUBIC implementation simulates growing
    // cwnd by values other than 1 segment size.
    if (bicTarget > segCwnd)
    {
        cnt = segCwnd / (bicTarget - segCwnd);
        NS_LOG_DEBUG("target>cwnd. cnt=" << cnt);
    }
    else
    {
        cnt = 100 * segCwnd;
    }

    if (m_lastMaxCwnd == 0 && cnt > m_cntClamp)
    {
        cnt = m_cntClamp;
    }

    if (m_tcpFriendliness)
    {
        double beta = CalculateAdaptiveBeta();

        auto scale = static_cast<uint32_t>(8 * (1024 + beta * 1024) / 3 /
                                   (1024 - beta * 1024));
        delta = (segCwnd * scale) >> 3;
        while (m_ackCnt > delta)
        {
            m_ackCnt -= delta;
            m_tcpCwnd++;
        }
        if (m_tcpCwnd > segCwnd)
        {
            delta = m_tcpCwnd - segCwnd;
            maxCnt = segCwnd / delta;
            if (cnt > maxCnt)
            {
                cnt = maxCnt;
            }
        }
    }

    // The maximum rate of cwnd increase CUBIC allows is 1 packet per
    // 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
    return std::max(cnt, 2U);
}

double
TcpCubicRtt::CalculateAdaptiveC() const
{
    if (m_delayMin == Time::Min() || m_rttReference <= Time(0))
    {
        return m_c;
    }

    double rttRatio = m_delayMin.GetSeconds() / m_rttReference.GetSeconds();
    double x = std::clamp(rttRatio - 1.0, -1.0, 1.0);

    return m_c * (1.0 + m_alpha * x);
}

double
TcpCubicRtt::CalculateAdaptiveBeta() const
{
    NS_ABORT_MSG_IF(m_betaMin > m_betaMax,
                    "BetaMin cannot be greater than BetaMax");

    if (m_delayMin == Time::Min() || m_rttReference <= Time(0))
    {
        return std::clamp(m_beta, m_betaMin, m_betaMax);
    }

    double rttRatio = m_delayMin.GetSeconds() / m_rttReference.GetSeconds();
    double x = std::clamp(rttRatio - 1.0, -1.0, 1.0);

    double beta = m_beta + m_gamma * x;

    return std::clamp(beta, m_betaMin, m_betaMax);
}

void
TcpCubicRtt::PktsAcked(Ptr<TcpSocketState> tcb, uint32_t segmentsAcked, const Time& rtt)
{
    NS_LOG_FUNCTION(this << tcb << segmentsAcked << rtt);

    /* Discard delay samples right after fast recovery */
    if (m_epochStart != Time::Min() && (Simulator::Now() - m_epochStart) < m_cubicDelta)
    {
        return;
    }

    /* first time call or link delay decreases */
    if (m_delayMin == Time::Min() || m_delayMin > rtt)
    {
        m_delayMin = rtt;
    }

    /* hystart triggers when cwnd is larger than some threshold */
    if (m_hystart && tcb->m_cWnd <= tcb->m_ssThresh &&
        tcb->m_cWnd >= m_hystartLowWindow * tcb->m_segmentSize)
    {
        HystartUpdate(tcb, rtt);
    }
}

void
TcpCubicRtt::HystartUpdate(Ptr<TcpSocketState> tcb, const Time& delay)
{
    NS_LOG_FUNCTION(this << delay);

    if (!m_found)
    {
        Time now = Simulator::Now();

        /* first detection parameter - ack-train detection */
        if ((now - m_lastAck) <= m_hystartAckDelta)
        {
            m_lastAck = now;

            if ((now - m_roundStart) > m_delayMin)
            {
                if (m_hystartDetect == HybridSSDetectionMode::PACKET_TRAIN ||
                    m_hystartDetect == HybridSSDetectionMode::BOTH)
                {
                    m_found = true;
                }
            }
        }

        /* obtain the minimum delay of more than sampling packets */
        if (m_sampleCnt < m_hystartMinSamples)
        {
            if (m_currRtt == Time::Min() || m_currRtt > delay)
            {
                m_currRtt = delay;
            }

            ++m_sampleCnt;
        }
        else if (m_currRtt > m_delayMin + HystartDelayThresh(m_delayMin))
        {
            if (m_hystartDetect == HybridSSDetectionMode::DELAY ||
                m_hystartDetect == HybridSSDetectionMode::BOTH)
            {
                m_found = true;
            }
        }

        /*
         * Either one of two conditions are met,
         * we exit from slow start immediately.
         */
        if (m_found)
        {
            NS_LOG_DEBUG("Exit from SS, immediately :-)");
            tcb->m_ssThresh = tcb->m_cWnd;
        }
    }
}

Time
TcpCubicRtt::HystartDelayThresh(const Time& t) const
{
    NS_LOG_FUNCTION(this << t);

    Time ret = t;
    if (t > m_hystartDelayMax)
    {
        ret = m_hystartDelayMax;
    }
    else if (t < m_hystartDelayMin)
    {
        ret = m_hystartDelayMin;
    }

    return ret;
}

uint32_t
TcpCubicRtt::GetSsThresh(Ptr<const TcpSocketState> tcb, uint32_t bytesInFlight)
{
    NS_LOG_FUNCTION(this << tcb << bytesInFlight);

    uint32_t segCwnd = tcb->GetCwndInSegments();
    double beta = CalculateAdaptiveBeta();
    NS_LOG_DEBUG("CUBIC-RTT: Loss response"
             << " | RTT min = " << m_delayMin.GetMilliSeconds() << " ms"
             << " | Beta adaptive = " << beta);

    NS_LOG_DEBUG("Loss at cWnd=" << segCwnd
                                 << " segments in flight=" << bytesInFlight / tcb->m_segmentSize);

    /* Wmax and fast convergence */
    if (segCwnd < m_lastMaxCwnd && m_fastConvergence)
    {
        m_lastMaxCwnd = (segCwnd * (1 + beta)) / 2;
    }
    else
    {
        m_lastMaxCwnd = segCwnd;
    }

    m_epochStart = Time::Min(); // end of epoch

    uint32_t ssThresh;
    if (tcb->m_abeEnabled && tcb->m_ecnState == TcpSocketState::ECN_ECE_RCVD)
    {
        ssThresh = std::max(static_cast<uint32_t>(segCwnd * m_betaEcn), 2U) *
                   tcb->m_segmentSize; // According to RFC 8511 (ABE)
    }
    else
    {
        ssThresh = std::max(static_cast<uint32_t>(segCwnd * beta), 2U) *
                   tcb->m_segmentSize;
    }

    NS_LOG_DEBUG("SsThresh = " << ssThresh);

    return ssThresh;
}

void
TcpCubicRtt::CongestionStateSet(Ptr<TcpSocketState> tcb, const TcpSocketState::TcpCongState_t newState)
{
    NS_LOG_FUNCTION(this << tcb << newState);

    if (newState == TcpSocketState::CA_LOSS)
    {
        CubicReset(tcb);
        HystartReset(tcb);
    }
}

void
TcpCubicRtt::CubicReset(Ptr<const TcpSocketState> tcb)
{
    NS_LOG_FUNCTION(this << tcb);

    m_bicOriginPoint = 0;
    m_cEpoch = 0.0;
    m_bicK = 0;
    m_ackCnt = 0;
    m_tcpCwnd = 0;
    m_delayMin = Time::Min();
    m_found = false;
}

Ptr<TcpCongestionOps>
TcpCubicRtt::Fork()
{
    NS_LOG_FUNCTION(this);
    return CopyObject<TcpCubicRtt>(this);
}

} // namespace ns3
