window.addEventListener("load", () => {
    const bar = document.querySelector(".riskfill");

    if (bar) {
        const width = bar.style.width;
        bar.style.width = "0%";

        setTimeout(() => {
            bar.style.width = width;
        }, 300);
    }

    const verdict = document.querySelector(".verdict");

    if (verdict) {
        const text = verdict.innerText.toLowerCase();

        if (text.includes("phishing")) {
            verdict.style.color = "#ef4444";
        } else if (text.includes("suspicious")) {
            verdict.style.color = "#facc15";
        } else {
            verdict.style.color = "#22c55e";
        }
    }
});
