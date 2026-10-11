"""
TrustMesh Architecture Diagram Generator
Programmatically renders a high-resolution, production-grade architectural blueprint
and exports both architecture.png and architecture.jpg to the project root directory.
Includes Linux Foundation A2A Standard Signed Agent Cards, Anthropic MCP Tool Gatekeeping,
and Human-in-the-Loop Step-Up Escalation.
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image

def generate_architecture_diagram():
    # Set high-DPI figure for ultra crisp 4000x2600 resolution
    fig = plt.figure(figsize=(20, 13), dpi=200)
    ax = fig.add_subplot(111)
    ax.set_facecolor("#090D16")
    fig.patch.set_facecolor("#090D16")

    # Set coordinate boundaries
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Helper function to draw rounded boxes
    def draw_box(x, y, w, h, bg_color, border_color, title, subtitle="", text_color="#FFFFFF", title_color="#38BDF8", title_size=11, sub_size=8.2, radius=1.4):
        rect = patches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad=0.5,rounding_size={radius}",
            facecolor=bg_color,
            edgecolor=border_color,
            linewidth=1.8,
            zorder=2
        )
        ax.add_patch(rect)
        if title:
            ax.text(x + w / 2, y + h - 2.6, title, ha="center", va="center", color=title_color, fontsize=title_size, fontweight="bold", zorder=3)
        if subtitle:
            ax.text(x + w / 2, y + h / 2 - 1.2, subtitle, ha="center", va="center", color=text_color, fontsize=sub_size, zorder=3, multialignment="center")

    # Helper function to draw arrows
    def draw_arrow(x1, y1, x2, y2, color="#38BDF8", style="->", lw=2, label=""):
        ax.annotate(
            label,
            xy=(x2, y2), xycoords="data",
            xytext=(x1, y1), textcoords="data",
            arrowprops=dict(arrowstyle=style, color=color, lw=lw, shrinkA=5, shrinkB=5, connectionstyle="arc3,rad=0"),
            ha="center", va="center", fontsize=8, color="#94A3B8", fontweight="semibold", zorder=4
        )

    # 1. HEADER SECTION
    ax.text(50, 97.2, "TrustMesh: Dynamic Agent-to-Agent Authorization Protocol", ha="center", va="center", color="#FFFFFF", fontsize=20, fontweight="bold")
    ax.text(50, 94.6, "Zero-Trust Multi-Agent Cryptographic Capability Delegation, A2A Discovery, MCP Defense & Step-Up Governance", ha="center", va="center", color="#38BDF8", fontsize=10.5)

    # 2. TIER 1: IDENTITY & A2A DISCOVERY (y: 77 to 91)
    draw_box(3, 77, 29, 14, "#111827", "#3B82F6", "Root Trust Authority", 
             "Human Principal / Master Organization\nEd25519 Master Keypair (did:key:z6MkRoot...)\nSelf-Certifying Identity (Zero Central CA)\nIssues Top-Level Capability Delegations", 
             title_color="#60A5FA")

    draw_box(35.5, 77, 29, 14, "#111827", "#06B6D4", "Linux Foundation A2A Standard", 
             "Signed Agent Cards (/.well-known/agent-card.json)\nPublic Key & Skill Advertisement Verification\nRFC 8785 Canonical JSON Digital Signature\nCross-Vendor Capability Discovery", 
             title_color="#22D3EE")

    draw_box(68, 77, 29, 14, "#111827", "#10B981", "Autonomous Mesh Agents", 
             "CrewAI Coordinator | AutoGen Specialist | LangGraph\nEd25519 Peer Keypairs (did:key:...)\nSigns Ephemeral Proof-of-Possession\nMonotonically Attenuated Sub-Tasks", 
             title_color="#34D399")

    draw_arrow(32, 84, 35.5, 84, color="#60A5FA", label="Root Delegation")
    draw_arrow(64.5, 84, 68, 84, color="#22D3EE", label="A2A Verified Card")

    # 3. TIER 2: CAPABILITY SCOPES & CRYPTOGRAPHIC DAG (y: 58 to 73)
    draw_box(3, 58, 46, 15, "#0F172A", "#8B5CF6", "UCAN Capability Delegation Chain (DAG)", 
             "• Monotonic Attenuation Invariant: Child Scope <= Parent Scope\n"
             "• Spend Ceilings: $1,000 -> $600 -> $450 (Strict Mathematical Bound)\n"
             "• Resource Wildcards: travel:* -> travel:flights:book\n"
             "• Predicate Caveats: Allowed Airlines ['American', 'Delta']\n"
             "• Canonical JCS Serialization (RFC 8785) & SHA-256 Token Digests", 
             title_color="#A78BFA", sub_size=8.3)

    draw_box(51, 58, 46, 15, "#0F172A", "#EC4899", "Proof-of-Possession (PoP) Envelope", 
             "• Ephemeral Request Header (X-TrustMesh-PoP)\n"
             "• Cryptographic Binding: Action + Resource + SHA256(Payload) + Nonce\n"
             "• Signed by Caller Private Key matching leaf token audience\n"
             "• Sliding Window Anti-Drift: +/- 60s tolerance (Replay Immunity)\n"
             "• Single-Use Nonce Cache: Prevents Token Harvesting & Interception", 
             title_color="#F472B6", sub_size=8.3)

    # 4. TIER 3: FRAMEWORK ADAPTERS & MCP GATEKEEPER (y: 38 to 54)
    draw_box(3, 38, 18, 16, "#1E1B4B", "#6366F1", "CrewAI Adapter", 
             "TrustMeshCrewAgent\nTrustMeshCrewTool\nTool Pre-execution Guard\nAutomatic PoP Stamping\nTask Sub-delegation", title_color="#818CF8")
    
    draw_box(22.5, 38, 18, 16, "#1E1B4B", "#6366F1", "AutoGen Adapter", 
             "TrustMeshAutoGenAgent\nConversableAgent Hooks\nMessage Bundle Signing\nDynamic Token Validation\nFiltered Inbox Pipeline", title_color="#818CF8")
    
    draw_box(42, 38, 18, 16, "#1E1B4B", "#6366F1", "LangGraph Adapter", 
             "TrustMeshLangGraphNode\nsecure_langgraph_node\nState Graph Interceptor\nNode Context Propagation\nReceipt Injection", title_color="#818CF8")

    draw_box(61.5, 38, 18, 16, "#1E1B4B", "#A855F7", "Anthropic MCP Guard", 
             "TrustMeshMCPToolGuard\nOWASP Excessive Agency Def.\nModel Context Protocol Tool\nZero-Trust Parameter Guard\nPrompt Injection Blocker", title_color="#C084FC")

    draw_box(81, 38, 16, 16, "#1E1B4B", "#6366F1", "FastAPI / HTTP", 
             "require_capability Guard\nTrustMeshClient (HTTPX)\nX25519 DH Handshake\nChaCha20-Poly1305\nHTTP 401/403 Enforcer", title_color="#818CF8")

    # 5. TIER 4: DYNAMIC ENFORCEMENT, STEP-UP GOVERNANCE & RED-TEAM (y: 9 to 34)
    draw_box(3, 9, 44, 25, "#022C22", "#059669", "Dynamic Policy Engine & Verification Core", 
             "1. Replay Defense: Single-use Nonce Cache & Time Drift Check (+/-60s)\n"
             "2. Identity Check: PoP Signature Verification == Caller DID\n"
             "3. Payload Integrity: Recomputed SHA256(body) == PoP Payload Hash\n"
             "4. Delegation Continuity: Recursive Signature DAG verification to Root\n"
             "5. Monotonic Verification: Child spend <= Parent spend; Caveats tighter\n"
             "6. Dynamic Revocation: Bloom Filter Registry (<150KB for 100k+ DIDs)\n"
             "7. Cryptographic Receipts: Immutable verifier-signed decision records\n"
             "8. Durable Storage: SQLite / Relational SQLAlchemy persistence\n"
             "9. High Throughput: 1,525+ req/sec zero-trust verification throughput", 
             title_color="#34D399", sub_size=8.2)

    draw_box(49, 9, 25, 25, "#271E02", "#F59E0B", "Human-in-the-Loop Step-Up", 
             "• Real-time Out-of-Scope Detection\n"
             "• Overspend Challenge Queue\n"
             "• Supervisor Ephemeral Waiver Token\n"
             "• Cryptographic Approval Stamping\n"
             "• Dynamic Policy Override (Time-limited)\n"
             "• Live SSE Dashboard Integration\n"
             "• Rejection & Budget Freeze Audit", 
             title_color="#FBBF24", sub_size=8.2)

    draw_box(76, 9, 21, 25, "#31101E", "#E11D48", "Adversary Threat Defense", 
             "[BLOCKED] 1. Identity Impersonation\n"
             "[BLOCKED] 2. Replay & Nonce Reuse\n"
             "[BLOCKED] 3. Privilege Escalation\n"
             "[BLOCKED] 4. Payload Spoofing (MITM)\n"
             "[BLOCKED] 5. Expired Token Injection\n"
             "[BLOCKED] 6. Broken Chain Tampering\n\n"
             "Red-Team Suite: 6/6 Blocked\n"
             "Zero False Positives", 
             title_color="#FB7185", sub_size=8.2)

    # Connecting Flow Arrows
    draw_arrow(82, 77, 82, 54, color="#10B981", label="Authenticated Requests")
    draw_arrow(50, 58, 50, 54, color="#38BDF8")
    draw_arrow(70.5, 38, 70.5, 34, color="#A855F7", label="MCP Tool Calls")
    draw_arrow(88, 38, 88, 34, color="#E11D48", label="Adversary Attacks")
    draw_arrow(25, 38, 25, 34, color="#059669", label="Zero-Trust Enforcement")

    # Footer Information Bar
    ax.text(50, 3.2, "NIST SP 800-207 Zero Trust Compliant  |  Linux Foundation A2A Standard  |  Anthropic MCP Protected  |  Pure Python & Offline Capable", 
            ha="center", va="center", color="#64748B", fontsize=9.5, fontweight="bold")

    plt.tight_layout()

    # Save to both PNG and JPG in root directory
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    png_path = os.path.join(root_dir, "architecture.png")
    jpg_path = os.path.join(root_dir, "architecture.jpg")

    plt.savefig(png_path, format="png", dpi=200, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)

    # Convert to high-quality JPG using Pillow
    with Image.open(png_path) as img:
        rgb_img = img.convert("RGB")
        rgb_img.save(jpg_path, format="JPEG", quality=95)

    print(f"Generated: {png_path}")
    print(f"Generated: {jpg_path}")

if __name__ == "__main__":
    generate_architecture_diagram()
