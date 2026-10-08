// A colony of pixelated bats with pulsing red eyes, flying across the page.
// Purely cosmetic: a fixed, click-through overlay that removes itself when
// the flight is over. Loaded (deferred) on every page.
//
// Triggers:
//   - the Konami code (up up down down left right left right B A)
//   - typing "nosferatu", "abyss" or "bats" anywhere outside a form field
//   - clicking the "Abyssal Arsenal" logo 5 times quickly
//   - an in-app success: a page that renders an element with a `data-bats`
//     attribute (its value, if any, is shown as a caption) -- Resurrection
//     bringing a failed unit back, a Reliquary backup or restore.
//
// Honors prefers-reduced-motion: one bat drifts slowly across, no flapping.
(function () {
  "use strict";

  // 17x8 pixel frames. '#' = body, 'o' = eye, '.' = empty.
  var WINGS_UP = [
    "#...............#",
    "##....#...#....##",
    "###...#####...###",
    "####.##o#o##.####",
    ".###############.",
    "..#####.#.#####..",
    "...##...#...##...",
    ".................",
  ];
  var WINGS_DOWN = [
    ".................",
    "......#...#......",
    "......#####......",
    "..#####o#o#####..",
    ".###############.",
    "##.####.#.####.##",
    "#....##...##....#",
    ".......#.#.......",
  ];
  var WIDTH = 17;
  var HEIGHT = 8;
  var SVG_NS = "http://www.w3.org/2000/svg";

  var KONAMI = [
    "ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown",
    "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a",
  ];
  var WORDS = ["nosferatu", "abyss", "bats"];
  var LOGO_CLICKS = 5;
  var LOGO_WINDOW_MS = 2500;

  var reducedMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var flying = false;

  function frame(rows, className) {
    var g = document.createElementNS(SVG_NS, "g");
    g.setAttribute("class", className);
    rows.forEach(function (row, y) {
      for (var x = 0; x < row.length; x++) {
        var ch = row.charAt(x);
        if (ch === ".") continue;
        var r = document.createElementNS(SVG_NS, "rect");
        r.setAttribute("x", x);
        r.setAttribute("y", y);
        r.setAttribute("width", 1);
        r.setAttribute("height", 1);
        r.setAttribute("class", ch === "o" ? "bat-eye" : "bat-body");
        g.appendChild(r);
      }
    });
    return g;
  }

  function makeBat(pixel) {
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + WIDTH + " " + HEIGHT);
    svg.setAttribute("width", WIDTH * pixel);
    svg.setAttribute("height", HEIGHT * pixel);
    svg.setAttribute("shape-rendering", "crispEdges");
    svg.setAttribute("class", "bat");
    svg.appendChild(frame(WINGS_UP, "bat-frame bat-up"));
    svg.appendChild(frame(WINGS_DOWN, "bat-frame bat-down"));
    return svg;
  }

  function rand(min, max) {
    return min + Math.random() * (max - min);
  }

  function launch(caption) {
    if (flying || !document.body) return;
    flying = true;

    var colony = document.createElement("div");
    colony.className = "bat-colony" + (reducedMotion ? " bat-colony-calm" : "");
    colony.setAttribute("aria-hidden", "true");
    document.body.appendChild(colony);

    var vw = window.innerWidth;
    var vh = window.innerHeight;
    var count = reducedMotion ? 1 : Math.round(rand(9, 15));
    // The whole colony flies one way, like a real swarm leaving a cave.
    var leftToRight = Math.random() < 0.5;
    var finished = 0;
    var longest = 0;

    for (var i = 0; i < count; i++) {
      var pixel = reducedMotion ? 4 : Math.round(rand(3, 6));
      var bat = makeBat(pixel);
      // Unsynchronized wingbeats look alive; synchronized ones look fake.
      bat.style.setProperty("--flap", rand(0.16, 0.3).toFixed(2) + "s");
      bat.style.setProperty("--flap-delay", "-" + rand(0, 0.3).toFixed(2) + "s");
      colony.appendChild(bat);

      var batWidth = WIDTH * pixel;
      var startX = leftToRight ? -batWidth - rand(0, 120) : vw + rand(0, 120);
      var endX = leftToRight ? vw + batWidth + 40 : -batWidth - 40;
      var baseY = reducedMotion ? vh * 0.3 : rand(vh * 0.08, vh * 0.75);
      var drift = reducedMotion ? 0 : rand(-vh * 0.2, vh * 0.2);
      var bob = reducedMotion ? 0 : rand(12, 45);
      var waves = rand(2.5, 4);
      var duration = reducedMotion ? 9000 : rand(3200, 6000);
      var delay = reducedMotion ? 0 : rand(0, 1400);
      longest = Math.max(longest, duration + delay);

      // A wavy path: straight across, bobbing up and down, drifting a little.
      var keyframes = [];
      var steps = 8;
      for (var s = 0; s <= steps; s++) {
        var t = s / steps;
        var x = startX + (endX - startX) * t;
        var y = baseY + drift * t + Math.sin(t * Math.PI * waves) * bob;
        keyframes.push({ transform: "translate(" + x + "px, " + y + "px)" });
      }
      var anim = bat.animate(keyframes, {
        duration: duration,
        delay: delay,
        easing: "linear",
        fill: "both",
      });
      anim.onfinish = function () {
        finished++;
        if (finished === count) done();
      };
    }

    var captionEl = null;
    if (caption) {
      captionEl = document.createElement("div");
      captionEl.className = "bat-caption";
      captionEl.textContent = caption;
      colony.appendChild(captionEl);
    }

    // A safety net in case an animation never reports finishing (a
    // backgrounded tab can pause them).
    var timeout = setTimeout(done, longest + 2000);

    function done() {
      clearTimeout(timeout);
      if (colony.parentNode) colony.parentNode.removeChild(colony);
      flying = false;
    }
  }

  function inFormField(target) {
    if (!target || !target.tagName) return false;
    var tag = target.tagName.toLowerCase();
    return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
  }

  // Konami code + typed words. Never while typing into a form -- a host
  // named "abyss-01" must not set off bats.
  var konamiPos = 0;
  var typed = "";
  document.addEventListener("keydown", function (e) {
    if (e.ctrlKey || e.metaKey || e.altKey || inFormField(e.target)) return;
    var key = e.key && e.key.length === 1 ? e.key.toLowerCase() : e.key;

    if (key === KONAMI[konamiPos]) {
      konamiPos++;
      if (konamiPos === KONAMI.length) {
        konamiPos = 0;
        launch();
        return;
      }
    } else {
      konamiPos = key === KONAMI[0] ? 1 : 0;
    }

    if (typeof key === "string" && key.length === 1 && /[a-z]/.test(key)) {
      typed = (typed + key).slice(-16);
      for (var i = 0; i < WORDS.length; i++) {
        if (typed.slice(-WORDS[i].length) === WORDS[i]) {
          typed = "";
          launch();
          return;
        }
      }
    }
  });

  // Rapid clicks on the logo.
  var clicks = [];
  document.addEventListener("click", function (e) {
    var logo = e.target && e.target.closest && e.target.closest(".topnav-brand");
    if (!logo) return;
    var now = Date.now();
    clicks = clicks.filter(function (t) {
      return now - t < LOGO_WINDOW_MS;
    });
    clicks.push(now);
    if (clicks.length >= LOGO_CLICKS) {
      clicks = [];
      launch();
    }
  });

  // An in-app success the server marked with data-bats.
  function fromMarker() {
    var marker = document.querySelector("[data-bats]");
    if (marker) {
      setTimeout(function () {
        launch(marker.getAttribute("data-bats") || "");
      }, 350);
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fromMarker);
  } else {
    fromMarker();
  }
})();
