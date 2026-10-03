/**
 * animations.js  —  AI Link Threat Analyzer
 * Professional upgrade: Three.js 3D particle field  +  GSAP cinematic animations.
 * All existing functionality preserved (loader, flag stagger, result reveal, etc.)
 * Nothing is hidden by default — every section stays visible.
 */
(function () {
  "use strict";

  var REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var MOBILE  = window.innerWidth < 768;
  var HAS3    = typeof THREE !== "undefined";
  var HASGSAP = typeof gsap !== "undefined";

  /* ============================================================
     UTILITY
     ============================================================ */
  function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

  function countUp(el, target, dur, fmt) {
    if (!el || isNaN(target)) return;
    if (HASGSAP) {
      var obj = { val: 0 };
      gsap.to(obj, {
        val: target, duration: dur / 1000,
        ease: "power3.out",
        onUpdate: function () {
          el.textContent = fmt ? fmt(obj.val) : Math.round(obj.val);
        }
      });
    } else {
      var s = performance.now();
      (function step(now) {
        var p = Math.min((now - s) / dur, 1);
        el.textContent = fmt ? fmt(target * easeOut(p)) : Math.round(target * easeOut(p));
        if (p < 1) requestAnimationFrame(step);
      })(performance.now());
    }
  }

  /* ============================================================
     1.  THREE.JS 3D PARTICLE FIELD  (hero background)
     ============================================================ */
  function init3DHero() {
    if (REDUCED || !HAS3) { init2DParticles(); return; }

    var hero = document.querySelector(".hero-section");
    if (!hero) return;

    /* canvas */
    var canvas = document.createElement("canvas");
    canvas.id = "heroCanvas";
    hero.insertBefore(canvas, hero.firstChild);

    var W = hero.offsetWidth, H = Math.max(hero.offsetHeight, 460);

    var renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);

    var scene  = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(60, W / H, 0.1, 1000);
    camera.position.z = 30;

    /* particle geometry */
    var COUNT = MOBILE ? 80 : 180;
    var positions = new Float32Array(COUNT * 3);
    var colors    = new Float32Array(COUNT * 3);
    var palette   = [
      new THREE.Color(0x2563eb),
      new THREE.Color(0x06b6d4),
      new THREE.Color(0x7c3aed),
      new THREE.Color(0x3b82f6),
    ];
    var velocities = [];

    for (var i = 0; i < COUNT; i++) {
      positions[i*3]   = (Math.random() - 0.5) * 60;
      positions[i*3+1] = (Math.random() - 0.5) * 40;
      positions[i*3+2] = (Math.random() - 0.5) * 20;
      var c = palette[Math.floor(Math.random() * palette.length)];
      colors[i*3] = c.r; colors[i*3+1] = c.g; colors[i*3+2] = c.b;
      velocities.push({
        x: (Math.random() - 0.5) * 0.015,
        y: (Math.random() - 0.5) * 0.015,
        z: (Math.random() - 0.5) * 0.008
      });
    }

    var geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("color",    new THREE.BufferAttribute(colors, 3));

    var mat = new THREE.PointsMaterial({
      size: MOBILE ? 0.18 : 0.22,
      vertexColors: true,
      transparent: true,
      opacity: 0.75,
      sizeAttenuation: true
    });
    var points = new THREE.Points(geo, mat);
    scene.add(points);

    /* connecting lines between close particles */
    var lineMat = new THREE.LineBasicMaterial({
      color: 0x2563eb, transparent: true, opacity: 0.08
    });
    var lineGeo = new THREE.BufferGeometry();
    var linePos = [];
    for (var a = 0; a < COUNT; a++) {
      for (var b = a + 1; b < COUNT; b++) {
        var dx = positions[a*3]   - positions[b*3];
        var dy = positions[a*3+1] - positions[b*3+1];
        var dz = positions[a*3+2] - positions[b*3+2];
        if (Math.sqrt(dx*dx+dy*dy+dz*dz) < 8) {
          linePos.push(positions[a*3],positions[a*3+1],positions[a*3+2]);
          linePos.push(positions[b*3],positions[b*3+1],positions[b*3+2]);
        }
      }
    }
    if (linePos.length) {
      lineGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(linePos), 3));
      scene.add(new THREE.LineSegments(lineGeo, lineMat));
    }

    /* ambient glow sphere */
    var glow = new THREE.Mesh(
      new THREE.SphereGeometry(3.5, 16, 16),
      new THREE.MeshBasicMaterial({ color: 0x2563eb, transparent: true, opacity: 0.04 })
    );
    scene.add(glow);

    /* mouse interaction */
    var mouseX = 0, mouseY = 0;
    document.addEventListener("mousemove", function (e) {
      mouseX = (e.clientX / window.innerWidth  - 0.5) * 2;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    });

    /* resize */
    window.addEventListener("resize", function () {
      W = hero.offsetWidth; H = Math.max(hero.offsetHeight, 460);
      renderer.setSize(W, H);
      camera.aspect = W / H;
      camera.updateProjectionMatrix();
    });

    /* animate */
    var clock = new THREE.Clock();
    function animate() {
      requestAnimationFrame(animate);
      var t = clock.getElapsedTime();
      var pos = geo.attributes.position.array;

      for (var k = 0; k < COUNT; k++) {
        pos[k*3]   += velocities[k].x;
        pos[k*3+1] += velocities[k].y;
        pos[k*3+2] += velocities[k].z;
        if (Math.abs(pos[k*3])   > 32) velocities[k].x *= -1;
        if (Math.abs(pos[k*3+1]) > 22) velocities[k].y *= -1;
        if (Math.abs(pos[k*3+2]) > 12) velocities[k].z *= -1;
      }
      geo.attributes.position.needsUpdate = true;

      /* gentle camera drift + mouse parallax */
      camera.position.x += (mouseX * 4 - camera.position.x) * 0.03;
      camera.position.y += (-mouseY * 3 - camera.position.y) * 0.03;
      points.rotation.y = t * 0.04;
      points.rotation.x = Math.sin(t * 0.02) * 0.05;
      glow.scale.setScalar(1 + Math.sin(t * 0.8) * 0.08);

      renderer.render(scene, camera);
    }
    animate();
  }

  /* fallback 2D canvas when Three.js not available */
  function init2DParticles() {
    var hero = document.querySelector(".hero-section");
    if (!hero) return;
    var canvas = document.createElement("canvas"); canvas.id = "heroCanvas";
    hero.insertBefore(canvas, hero.firstChild);
    var ctx = canvas.getContext("2d"), W, H;
    var COUNT = MOBILE ? 20 : 50;
    var cols  = ["rgba(37,99,235,","rgba(6,182,212,","rgba(124,58,237,"];
    function resize(){ W=canvas.width=hero.offsetWidth; H=canvas.height=hero.offsetHeight||500; }
    resize(); window.addEventListener("resize", resize);
    function mk(){ return {x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-0.5)*0.35,vy:(Math.random()-0.5)*0.35,r:Math.random()*2+1,col:cols[Math.floor(Math.random()*3)],a:Math.random()*0.3+0.1}; }
    var pts=Array.from({length:COUNT},mk);
    (function draw(){
      ctx.clearRect(0,0,W,H);
      pts.forEach(function(p){ p.x+=p.vx; p.y+=p.vy; if(p.x<0)p.x=W; if(p.x>W)p.x=0; if(p.y<0)p.y=H; if(p.y>H)p.y=0; ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2); ctx.fillStyle=p.col+p.a+")"; ctx.fill(); });
      requestAnimationFrame(draw);
    })();
  }

  /* ============================================================
     2.  GSAP PAGE-IN  (hero elements appear on load)
     ============================================================ */
  function initPageIn() {
    if (REDUCED || !HASGSAP) return;
    var tl = gsap.timeline({ delay: 0.1 });
    tl.from(".hero-icon-wrap",  { duration: 0.7, scale: 0.7, opacity: 0, ease: "back.out(1.7)" }, 0)
      .from(".hero-title",      { duration: 0.6, y: 30, opacity: 0, ease: "power3.out" }, 0.15)
      .from(".hero-subtitle",   { duration: 0.6, y: 20, opacity: 0, ease: "power3.out" }, 0.25)
      .from(".scanner-card",    { duration: 0.6, y: 24, opacity: 0, ease: "power3.out" }, 0.35)
      .from(".btn-example",     { duration: 0.4, y: 10, opacity: 0, stagger: 0.05, ease: "power2.out" }, 0.55);
  }

  /* ============================================================
     3.  GSAP SCROLL REVEALS
     ============================================================ */
  function initScrollReveal() {
    if (!HASGSAP) {
      /* CSS fallback */
      var obs = new IntersectionObserver(function(entries) {
        entries.forEach(function(e) {
          if (!e.isIntersecting) return;
          setTimeout(function(){ e.target.classList.add("revealed"); }, parseInt(e.target.dataset.delay)||0);
          obs.unobserve(e.target);
        });
      }, { threshold: 0.1 });
      document.querySelectorAll(".reveal-on-scroll").forEach(function(el){ obs.observe(el); });
      return;
    }

    if (typeof ScrollTrigger !== "undefined") {
      gsap.registerPlugin(ScrollTrigger);
    }

    /* Threat category cards staggered reveal */
    var threatCards = document.querySelectorAll(".threat-card");
    if (threatCards.length && typeof ScrollTrigger !== "undefined") {
      gsap.from(threatCards, {
        scrollTrigger: { trigger: ".info-section", start: "top 80%" },
        duration: 0.6, y: 40, opacity: 0, scale: 0.92,
        stagger: 0.12, ease: "power3.out"
      });
    } else {
      var obs2 = new IntersectionObserver(function(entries) {
        entries.forEach(function(e) {
          if (!e.isIntersecting) return;
          setTimeout(function(){ e.target.classList.add("revealed"); }, parseInt(e.target.dataset.delay)||0);
          obs2.unobserve(e.target);
        });
      }, { threshold: 0.1 });
      document.querySelectorAll(".reveal-on-scroll").forEach(function(el){ obs2.observe(el); });
    }
  }

  /* ============================================================
     4.  HERO ICON — GSAP floating + orbit ring
     ============================================================ */
  function initHeroIcon() {
    if (REDUCED) return;
    var wrap = document.querySelector(".hero-icon-wrap");
    if (!wrap) return;

    /* orbit ring */
    if (!wrap.querySelector(".hero-orbit-ring")) {
      var ring = document.createElement("div"); ring.className = "hero-orbit-ring";
      wrap.appendChild(ring);
    }

    /* GSAP floating */
    if (HASGSAP) {
      gsap.to(wrap, {
        y: -10, duration: 2.8,
        ease: "sine.inOut", yoyo: true, repeat: -1
      });
      /* icon icon pulse */
      var ic = wrap.querySelector("i");
      if (ic) gsap.to(ic, { scale: 1.05, duration: 2, ease: "sine.inOut", yoyo: true, repeat: -1 });
    }
  }

  /* ============================================================
     5.  MOUSE PARALLAX ON HERO
     ============================================================ */
  function initParallax() {
    if (REDUCED || MOBILE) return;
    var hero = document.querySelector(".hero-section");
    var icon = document.querySelector(".hero-icon-wrap");
    if (!hero || !icon) return;
    hero.addEventListener("mousemove", function (e) {
      var r = hero.getBoundingClientRect();
      var dx = ((e.clientX - r.left) / r.width  - 0.5) * 14;
      var dy = ((e.clientY - r.top)  / r.height - 0.5) * 10;
      if (HASGSAP) {
        gsap.to(icon, { x: dx, y: dy, duration: 0.6, ease: "power2.out", overwrite: "auto" });
      } else {
        icon.style.transform = "translate(" + dx + "px," + dy + "px)";
      }
    });
    hero.addEventListener("mouseleave", function () {
      if (HASGSAP) gsap.to(icon, { x: 0, y: 0, duration: 0.8, ease: "power2.out" });
      else icon.style.transform = "";
    });
  }

  /* ============================================================
     6.  SCAN LINE
     ============================================================ */
  function initScanLine() {
    if (REDUCED) return;
    var wrap = document.querySelector(".hero-icon-wrap");
    if (!wrap) return;
    wrap.style.position = "relative"; wrap.style.overflow = "hidden";
    function fire() {
      var l = document.createElement("div"); l.className = "scan-line";
      wrap.appendChild(l);
      if (HASGSAP) {
        gsap.fromTo(l, { top: "0%", opacity: 1 }, {
          top: "100%", opacity: 0, duration: 1.5, ease: "none",
          onComplete: function() { if (l.parentNode) l.parentNode.removeChild(l); }
        });
      } else {
        setTimeout(function(){ if(l.parentNode) l.parentNode.removeChild(l); }, 1600);
      }
    }
    fire(); setInterval(fire, 4000);
  }

  /* ============================================================
     7.  URL INPUT GLOW
     ============================================================ */
  function initInputGlow() {
    var inp = document.getElementById("urlInput");
    var grp = inp && inp.closest(".url-input-group");
    if (!inp || !grp) return;
    inp.addEventListener("focus", function () {
      grp.classList.add("url-input-focused");
      if (HASGSAP) gsap.to(grp, { scale: 1.01, duration: 0.2, ease: "power2.out" });
    });
    inp.addEventListener("blur", function () {
      grp.classList.remove("url-input-focused");
      if (HASGSAP) gsap.to(grp, { scale: 1, duration: 0.2, ease: "power2.out" });
    });
  }

  /* ============================================================
     8.  ANALYZE BUTTON  (GSAP micro-interactions)
     ============================================================ */
  function initButtonStates() {
    var btn = document.getElementById("analyzeBtn");
    if (!btn) return;
    var origHTML = btn.innerHTML;

    /* hover */
    if (HASGSAP && !MOBILE) {
      btn.addEventListener("mouseenter", function () {
        gsap.to(btn, { scale: 1.04, duration: 0.2, ease: "power2.out" });
      });
      btn.addEventListener("mouseleave", function () {
        gsap.to(btn, { scale: 1, duration: 0.2, ease: "power2.out" });
      });
      btn.addEventListener("mousedown", function () {
        gsap.to(btn, { scale: 0.97, duration: 0.1, ease: "power2.in" });
      });
      btn.addEventListener("mouseup",   function () {
        gsap.to(btn, { scale: 1, duration: 0.15, ease: "back.out(2)" });
      });
    }

    var ls = document.getElementById("loadingSection");
    if (!ls) return;
    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        if (m.attributeName !== "class") return;
        var loading = !ls.classList.contains("d-none");
        if (loading) {
          btn.innerHTML = '<span class="btn-spin-ring me-2"></span>SCANNING...';
          btn.classList.add("scanning");
        } else {
          btn.innerHTML = origHTML;
          btn.classList.remove("scanning");
        }
      });
    }).observe(ls, { attributes: true });
  }

  /* ============================================================
     9.  CINEMATIC LOADER (GSAP step animations)
     ============================================================ */
  function initCinematicLoader() {
    var ls = document.getElementById("loadingSection"); if (!ls) return;
    var steps = [
      { i:"bi-cpu",            t:"Initializing AI Scanner",    d:480 },
      { i:"bi-list-check",     t:"Extracting 34 URL Features", d:650 },
      { i:"bi-diagram-3-fill", t:"Running ML Classification",  d:600 },
      { i:"bi-speedometer2",   t:"Calculating Risk Score",     d:420 },
      { i:"bi-check2-circle",  t:"Preparing Results",          d:280 },
    ];
    var active = false, timer = null, step = 0;

    function build() {
      var h = '<div class="cinema-loader text-center py-4">';
      h += '<div class="neural-wrap mx-auto mb-3"><div class="neural-ring"></div><div class="neural-outer"></div></div>';
      h += '<div class="scan-steps">';
      steps.forEach(function (s, i) {
        h += '<div class="scan-step" id="cs' + i + '"><i class="bi ' + s.i + ' scan-step-icon"></i><span>' + s.t + '</span><span class="ms-auto" id="ss' + i + '"></span></div>';
      });
      return h + '</div></div>';
    }

    function act(i) {
      var el = document.getElementById("cs" + i); if (!el) return;
      el.classList.add("active");
      var st = document.getElementById("ss" + i);
      if (st) st.innerHTML = '<span class="step-dot-anim text-muted"></span>';
      if (HASGSAP) gsap.fromTo(el, { x: -8, opacity: 0 }, { x: 0, opacity: 1, duration: 0.3, ease: "power2.out" });
    }
    function done(i) {
      var el = document.getElementById("cs" + i); if (!el) return;
      el.classList.remove("active"); el.classList.add("done");
      var st = document.getElementById("ss" + i);
      if (st) st.innerHTML = '<i class="bi bi-check2 text-success"></i>';
      if (HASGSAP) gsap.to(el, { x: 4, duration: 0.15, yoyo: true, repeat: 1, ease: "power1.inOut" });
    }
    function run() {
      step = 0;
      (function next() {
        if (!active) return;
        if (step > 0) done(step - 1);
        if (step >= steps.length) return;
        act(step);
        timer = setTimeout(function () { step++; next(); }, steps[step].d);
      })();
    }

    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        if (m.attributeName !== "class") return;
        var vis = !ls.classList.contains("d-none");
        if (vis && !active) {
          active = true;
          var card = ls.querySelector(".loading-card");
          if (card) {
            var d = document.createElement("div"); d.id = "csteps"; d.innerHTML = build();
            card.appendChild(d);
          }
          run();
        } else if (!vis && active) {
          active = false; clearTimeout(timer); step = 0;
          var d2 = document.getElementById("csteps");
          if (d2 && d2.parentNode) d2.parentNode.removeChild(d2);
        }
      });
    }).observe(ls, { attributes: true });
  }

  /* ============================================================
     10. RESULT REVEAL  (GSAP cinematic reveal)
     ============================================================ */
  function initResultAnimations() {
    var rs = document.getElementById("resultSection");
    var rc = document.getElementById("resultCard");
    if (!rs || !rc) return;

    function staggerEl(sel, cls, delay) {
      (function retry(n) {
        var els = document.querySelectorAll(sel + ":not(." + cls + ")");
        if (!els.length && n < 15) { setTimeout(function () { retry(n + 1); }, 60); return; }
        if (HASGSAP) {
          gsap.fromTo(Array.from(els),
            { y: 10, opacity: 0 },
            { y: 0, opacity: 1, duration: 0.3, stagger: delay / 1000, ease: "power2.out",
              onStart: function () { els.forEach(function(e){ e.classList.add(cls); }); }
            }
          );
        } else {
          els.forEach(function (e, i) {
            setTimeout(function () { e.classList.add(cls); }, i * delay);
          });
        }
      })(0);
    }

    new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        if (m.attributeName !== "class" || rs.classList.contains("d-none")) return;

        if (HASGSAP) {
          gsap.fromTo(rc,
            { scale: 0.94, opacity: 0, y: 16 },
            { scale: 1, opacity: 1, y: 0, duration: 0.45, ease: "back.out(1.5)" }
          );
        } else {
          rc.classList.add("result-reveal");
          setTimeout(function () { rc.classList.remove("result-reveal"); }, 400);
        }

        /* glow by prediction */
        var pred = (document.getElementById("resultPrediction") || {}).textContent || "";
        var glowMap = { SAFE:"glow-safe", SUSPICIOUS:"glow-suspicious", PHISHING:"glow-phishing", MALICIOUS:"glow-malicious" };
        var gc = glowMap[pred.trim().toUpperCase()];
        if (gc) {
          rc.classList.add(gc);
          setTimeout(function () { rc.classList.remove(gc); }, 2500);
        }

        /* animate numbers */
        var re = document.getElementById("riskScore");
        var ce = document.getElementById("confidenceVal");
        var cr = re ? (parseInt(re.textContent) || 0) : 0;
        var cc = ce ? (parseFloat(ce.textContent) || 0) : 0;
        if (re) re.textContent = "0/100";
        if (ce) ce.textContent = "0.0%";
        setTimeout(function () {
          countUp(re, cr, 900, function (v) { return Math.round(v) + "/100"; });
          countUp(ce, cc, 700, function (v) { return v.toFixed(1) + "%"; });
        }, 120);

        /* risk bar GSAP */
        var bar = document.getElementById("riskBar");
        if (bar && HASGSAP) {
          gsap.fromTo(bar, { width: "0%" }, { width: cr + "%", duration: 1.0, ease: "power3.out", delay: 0.12 });
        }

        /* stagger flags + chips */
        setTimeout(function () { staggerEl("#flagList .flag-item",    "flag-visible", 80); }, 100);
        setTimeout(function () { staggerEl("#featureGrid .feature-chip", "chip-visible", 50); }, 80);

        /* metric cards pop-in */
        if (HASGSAP) {
          var metrics = document.querySelectorAll(".metric-card");
          if (metrics.length) {
            gsap.fromTo(metrics,
              { y: 12, opacity: 0, scale: 0.95 },
              { y: 0, opacity: 1, scale: 1, duration: 0.4, stagger: 0.08, ease: "back.out(1.4)", delay: 0.1 }
            );
          }
        }
      });
    }).observe(rs, { attributes: true });

    /* watch for DOM changes */
    var fl = document.getElementById("flagList");
    if (fl) new MutationObserver(function () {
      setTimeout(function () { staggerEl("#flagList .flag-item", "flag-visible", 80); }, 30);
    }).observe(fl, { childList: true });

    var fg = document.getElementById("featureGrid");
    if (fg) new MutationObserver(function () {
      setTimeout(function () { staggerEl("#featureGrid .feature-chip", "chip-visible", 50); }, 30);
    }).observe(fg, { childList: true });
  }

  /* ============================================================
     11. THREAT CARD HOVER  (GSAP)
     ============================================================ */
  function initThreatCards() {
    document.querySelectorAll(".threat-card").forEach(function (card) {
      var ic = card.querySelector(".threat-icon");
      if (!ic) return;
      card.addEventListener("mouseenter", function () {
        if (HASGSAP) {
          gsap.to(card, { y: -6, scale: 1.03, duration: 0.25, ease: "power2.out" });
          gsap.to(ic,   { scale: 1.15, rotation: -5, duration: 0.25, ease: "back.out(2)" });
        } else {
          ic.style.transform = "scale(1.12) rotate(-4deg)";
          ic.style.transition = "transform 0.2s ease";
        }
      });
      card.addEventListener("mouseleave", function () {
        if (HASGSAP) {
          gsap.to(card, { y: 0, scale: 1, duration: 0.3, ease: "power2.out" });
          gsap.to(ic,   { scale: 1, rotation: 0, duration: 0.3, ease: "power2.out" });
        } else {
          ic.style.transform = "";
        }
      });
    });
  }

  /* ============================================================
     12. STAT CARD HOVER  (GSAP lift)
     ============================================================ */
  function initStatCards() {
    if (!HASGSAP || MOBILE) return;
    document.querySelectorAll(".stat-card").forEach(function (card) {
      card.addEventListener("mouseenter", function () {
        gsap.to(card, { y: -4, scale: 1.04, duration: 0.22, ease: "power2.out" });
      });
      card.addEventListener("mouseleave", function () {
        gsap.to(card, { y: 0, scale: 1, duration: 0.25, ease: "power2.out" });
      });
    });
  }

  /* ============================================================
     13. CHART CARDS  GSAP fade-in on scroll
     ============================================================ */
  function initChartCards() {
    if (!HASGSAP || typeof ScrollTrigger === "undefined") return;
    gsap.registerPlugin(ScrollTrigger);
    document.querySelectorAll(".chart-card").forEach(function (card) {
      gsap.from(card, {
        scrollTrigger: { trigger: card, start: "top 88%", once: true },
        y: 24, opacity: 0, duration: 0.5, ease: "power3.out"
      });
    });
  }

  /* ============================================================
     14. NAV LINK HOVER  (GSAP underline)
     ============================================================ */
  function initNavHover() {
    if (!HASGSAP) return;
    document.querySelectorAll(".navbar-custom .nav-link").forEach(function (link) {
      link.addEventListener("mouseenter", function () {
        gsap.to(link, { scale: 1.05, duration: 0.15, ease: "power1.out" });
      });
      link.addEventListener("mouseleave", function () {
        gsap.to(link, { scale: 1, duration: 0.2, ease: "power1.out" });
      });
    });
  }

  /* ============================================================
     15. SCAN HISTORY TABLE ROW HOVER  (GSAP)
     ============================================================ */
  function initTableRows() {
    if (!HASGSAP) return;
    function attachRow(tr) {
      tr.addEventListener("mouseenter", function () {
        gsap.to(tr, { x: 3, duration: 0.15, ease: "power1.out" });
      });
      tr.addEventListener("mouseleave", function () {
        gsap.to(tr, { x: 0, duration: 0.2, ease: "power1.out" });
      });
    }
    document.querySelectorAll(".table-dark tbody tr").forEach(attachRow);

    /* watch for dynamically added rows */
    document.querySelectorAll(".table-dark tbody").forEach(function (tbody) {
      new MutationObserver(function (muts) {
        muts.forEach(function (m) {
          m.addedNodes.forEach(function (n) {
            if (n.nodeName === "TR") attachRow(n);
          });
        });
      }).observe(tbody, { childList: true });
    });
  }

  /* ============================================================
     INIT
     ============================================================ */
  document.addEventListener("DOMContentLoaded", function () {
    init3DHero();
    initPageIn();
    initParallax();
    initScanLine();
    initInputGlow();
    initButtonStates();
    initCinematicLoader();
    initResultAnimations();
    initScrollReveal();
    initThreatCards();
    initStatCards();
    initChartCards();
    initNavHover();
    initTableRows();
    initHeroIcon();
  });

})();