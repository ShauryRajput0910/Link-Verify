/**
 * ============================================================================
 * LINKVERIFY - 3D Interactive Floating Cyber Engine (IIT Bombay Tech Style)
 * ============================================================================
 */

(function () {
    "use strict";

    // Initialize after DOM loads
    window.addEventListener("DOMContentLoaded", () => {
        initCyber3DCanvas();
        init3DCardTilt();
        initHeroParallax();
        initGlowingCursor();
    });

    /**
     * 1. 3D Interactive Cyber Space Canvas
     * Renders 3D floating nodes, constellation lines, and a rotating 3D wireframe core.
     */
    function initCyber3DCanvas() {
        const canvas = document.getElementById("cyber3DCanvas");
        if (!canvas) return;

        const ctx = canvas.getContext("2d");
        let width = (canvas.width = window.innerWidth);
        let height = (canvas.height = window.innerHeight);

        let mouseX = width / 2;
        let mouseY = height / 2;
        let targetRotX = 0;
        let targetRotY = 0;
        let rotX = 0;
        let rotY = 0;

        // Resize handler
        window.addEventListener("resize", () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        // Mouse move parallax
        window.addEventListener("mousemove", (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
            targetRotY = ((mouseX - width / 2) / (width / 2)) * 0.45;
            targetRotX = -((mouseY - height / 2) / (height / 2)) * 0.35;
        });

        // 3D Particles
        const particleCount = Math.min(width > 768 ? 90 : 45, 100);
        const particles = [];
        const fov = 350;

        for (let i = 0; i < particleCount; i++) {
            particles.push({
                x: (Math.random() - 0.5) * 1400,
                y: (Math.random() - 0.5) * 1000,
                z: (Math.random() - 0.5) * 1000,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                vz: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 2 + 1.2,
                color: i % 4 === 0 ? "#00f0ff" : i % 3 === 0 ? "#00ff9d" : "#7000ff"
            });
        }

        // 3D Wireframe Icosahedron (Cyber Core)
        const phi = (1 + Math.sqrt(5)) / 2;
        const baseVertices = [
            [-1, phi, 0], [1, phi, 0], [-1, -phi, 0], [1, -phi, 0],
            [0, -1, phi], [0, 1, phi], [0, -1, -phi], [0, 1, -phi],
            [phi, 0, -1], [phi, 0, 1], [-phi, 0, -1], [-phi, 0, 1]
        ].map(v => {
            const mag = Math.hypot(...v);
            return [v[0] / mag * 180, v[1] / mag * 180, v[2] / mag * 180];
        });

        const edges = [
            [0, 11], [0, 5], [0, 1], [0, 7], [0, 10],
            [1, 5], [5, 11], [11, 10], [10, 7], [7, 1],
            [3, 9], [3, 4], [3, 2], [3, 6], [3, 8],
            [4, 9], [9, 8], [8, 6], [6, 2], [2, 4],
            [5, 9], [11, 4], [10, 2], [7, 6], [1, 8],
            [0, 3]
        ];

        let coreAngle = 0;

        function rotateX3D(x, y, z, angle) {
            const cos = Math.cos(angle);
            const sin = Math.sin(angle);
            return [x, y * cos - z * sin, y * sin + z * cos];
        }

        function rotateY3D(x, y, z, angle) {
            const cos = Math.cos(angle);
            const sin = Math.sin(angle);
            return [x * cos + z * sin, y, -x * sin + z * cos];
        }

        function project(x, y, z) {
            const scale = fov / (fov + z + 500);
            return {
                x: width / 2 + x * scale,
                y: height / 2 + y * scale,
                scale: scale
            };
        }

        function animate() {
            ctx.clearRect(0, 0, width, height);

            // Smooth rotation interpolation
            rotX += (targetRotX - rotX) * 0.05;
            rotY += (targetRotY - rotY) * 0.05;
            coreAngle += 0.008;

            // Draw 3D wireframe core
            const projectedVertices = baseVertices.map(v => {
                let [x, y, z] = rotateY3D(v[0], v[1], v[2], coreAngle + rotY);
                [x, y, z] = rotateX3D(x, y, z, coreAngle * 0.7 + rotX);
                // Shift core to right side on desktop where hero visual is
                const offsetX = width > 960 ? width * 0.22 : 0;
                return project(x + offsetX, y - 20, z);
            });

            // Draw core edges
            ctx.strokeStyle = "rgba(0, 240, 255, 0.25)";
            ctx.lineWidth = 1.2;
            ctx.beginPath();
            for (const [i, j] of edges) {
                if (projectedVertices[i] && projectedVertices[j]) {
                    ctx.moveTo(projectedVertices[i].x, projectedVertices[i].y);
                    ctx.lineTo(projectedVertices[j].x, projectedVertices[j].y);
                }
            }
            ctx.stroke();

            // Draw core vertices glowing dots
            for (const p of projectedVertices) {
                ctx.fillStyle = "#00ff9d";
                ctx.beginPath();
                ctx.arc(p.x, p.y, Math.max(1.5, 3.5 * p.scale), 0, Math.PI * 2);
                ctx.fill();
            }

            // Update & Draw 3D Particle Cloud
            const projectedParticles = [];
            for (let i = 0; i < particles.length; i++) {
                const p = particles[i];

                p.x += p.vx;
                p.y += p.vy;
                p.z += p.vz;

                if (p.x < -700) p.x = 700;
                if (p.x > 700) p.x = -700;
                if (p.y < -500) p.y = 500;
                if (p.y > 500) p.y = -500;
                if (p.z < -500) p.z = 500;
                if (p.z > 500) p.z = -500;

                let [rx, ry, rz] = rotateY3D(p.x, p.y, p.z, rotY * 0.6);
                [rx, ry, rz] = rotateX3D(rx, ry, rz, rotX * 0.6);

                const proj = project(rx, ry, rz);
                projectedParticles.push({ ...proj, color: p.color, radius: p.radius });

                // Render particle
                ctx.fillStyle = p.color;
                ctx.globalAlpha = Math.min(1, Math.max(0.2, proj.scale * 1.3));
                ctx.beginPath();
                ctx.arc(proj.x, proj.y, Math.max(1, p.radius * proj.scale), 0, Math.PI * 2);
                ctx.fill();
            }

            // Draw constellation lines between nearby 3D particles
            ctx.lineWidth = 0.6;
            for (let i = 0; i < projectedParticles.length; i++) {
                for (let j = i + 1; j < projectedParticles.length; j++) {
                    const dx = projectedParticles[i].x - projectedParticles[j].x;
                    const dy = projectedParticles[i].y - projectedParticles[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 110) {
                        ctx.strokeStyle = "rgba(0, 240, 255, " + (1 - dist / 110) * 0.2 + ")";
                        ctx.beginPath();
                        ctx.moveTo(projectedParticles[i].x, projectedParticles[i].y);
                        ctx.lineTo(projectedParticles[j].x, projectedParticles[j].y);
                        ctx.stroke();
                    }
                }
            }
            ctx.globalAlpha = 1;

            requestAnimationFrame(animate);
        }

        requestAnimationFrame(animate);
    }

    /**
     * 2. 3D Card Interactive Tilt & Specular Shine
     */
    function init3DCardTilt() {
        const tiltCards = document.querySelectorAll(
            ".tilt-card, .process-card, .threat-card, .feature-card, .team-card, .preview-panel, .analysis-box"
        );

        tiltCards.forEach((card) => {
            card.classList.add("preserve-3d");

            card.addEventListener("mousemove", (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                const centerX = rect.width / 2;
                const centerY = rect.height / 2;

                const rotateX = ((centerY - y) / centerY) * 12; // deg
                const rotateY = ((x - centerX) / centerX) * 12; // deg

                card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateZ(10px)`;

                // Update dynamic shine if card has shine element
                let shine = card.querySelector(".card-shine");
                if (!shine) {
                    shine = document.createElement("div");
                    shine.className = "card-shine";
                    card.appendChild(shine);
                }
                const percentX = (x / rect.width) * 100;
                const percentY = (y / rect.height) * 100;
                shine.style.background = `radial-gradient(circle at ${percentX}% ${percentY}%, rgba(0, 240, 255, 0.18), transparent 70%)`;
            });

            card.addEventListener("mouseleave", () => {
                card.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)";
                const shine = card.querySelector(".card-shine");
                if (shine) {
                    shine.style.background = "transparent";
                }
            });
        });
    }

    /**
     * 3. 3D Parallax on Hero Visual Satellite Cards
     */
    function initHeroParallax() {
        const heroSection = document.querySelector(".hero");
        const satCards = document.querySelectorAll(".floating-card-3d");
        if (!heroSection || satCards.length === 0) return;

        heroSection.addEventListener("mousemove", (e) => {
            const rect = heroSection.getBoundingClientRect();
            const relX = (e.clientX - rect.left) / rect.width - 0.5;
            const relY = (e.clientY - rect.top) / rect.height - 0.5;

            satCards.forEach((card) => {
                const depth = parseFloat(card.getAttribute("data-depth") || "30");
                const moveX = relX * depth;
                const moveY = relY * depth;
                card.style.transform = `translate3d(${moveX}px, ${moveY}px, ${depth}px) rotateX(${-relY * 18}deg) rotateY(${relX * 18}deg)`;
            });
        });

        heroSection.addEventListener("mouseleave", () => {
            satCards.forEach((card) => {
                card.style.transform = "translate3d(0, 0, 0) rotateX(0deg) rotateY(0deg)";
            });
        });
    }

    /**
     * 4. Futuristic Glowing Cursor Follower
     */
    function initGlowingCursor() {
        // Only enable on desktop
        if (window.innerWidth < 1024) return;

        const cursorDot = document.createElement("div");
        cursorDot.className = "cyber-cursor-glow";
        document.body.appendChild(cursorDot);

        let mouseX = -100;
        let mouseY = -100;
        let curX = -100;
        let curY = -100;

        window.addEventListener("mousemove", (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
        });

        function renderCursor() {
            curX += (mouseX - curX) * 0.15;
            curY += (mouseY - curY) * 0.15;
            cursorDot.style.transform = `translate3d(${curX}px, ${curY}px, 0)`;
            requestAnimationFrame(renderCursor);
        }
        requestAnimationFrame(renderCursor);
    }
})();

// Helper function for demo sample buttons
window.loadSample = function (url) {
    const input = document.getElementById("urlInput");
    if (input) {
        input.value = url;
        input.focus();
        if (typeof window.verifyLink === "function") {
            window.verifyLink();
        }
    }
};

