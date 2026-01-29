# Balanced, explainable risk scoring engine

SENSITIVE_PORTS = {21, 22, 23, 25, 3389, 445, 1433, 3306}

class RiskEngine:
    def compute_risk(self, flow):
        reasons = []
        score = 0.0

        pps = flow.packets_per_second()
        port_diversity = len(flow.unique_dst_ports)
        duration = flow.duration()

        # --- Packet rate factor ---
        if pps > 100:
            score += 0.35
            reasons.append("High packet rate")
        elif pps > 40:
            score += 0.20
            reasons.append("Moderate packet rate")

        # --- Port diversity factor ---
        if port_diversity > 20:
            score += 0.30
            reasons.append("High port diversity")
        elif port_diversity > 8:
            score += 0.15
            reasons.append("Moderate port diversity")

        # --- Burst duration factor ---
        if duration < 10 and flow.packet_count > 50:
            score += 0.20
            reasons.append("Short burst traffic")

        # --- Sensitive port factor ---
        if any(p in SENSITIVE_PORTS for p in flow.unique_dst_ports):
            score += 0.15
            reasons.append("Sensitive port access")

        # Clamp score to [0, 1]
        score = min(score, 1.0)

        return score, reasons

