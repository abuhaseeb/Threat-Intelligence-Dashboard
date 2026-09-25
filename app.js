(function () {
  "use strict";

  const categorySwitch = document.querySelectorAll(".category-switch__btn");
  const categoryViews = document.querySelectorAll(".category-view");
  const rowTemplate = document.getElementById("row-template");

  // ------------------------------------------------------------------
  // Category tabs (Social media / Research blogs)
  // ------------------------------------------------------------------
  categorySwitch.forEach((btn) => {
    btn.addEventListener("click", () => {
      const category = btn.dataset.category;

      categorySwitch.forEach((b) => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });

      categoryViews.forEach((view) => {
        view.hidden = view.dataset.category !== category;
      });
    });
  });

  // ------------------------------------------------------------------
  // Platform tabs within each category
  // ------------------------------------------------------------------
  document.querySelectorAll(".category-view").forEach((view) => {
    const tabButtons = view.querySelectorAll(".platform-tabs__btn");
    const panels = view.querySelectorAll(".panel");

    function activate(platformKey) {
      tabButtons.forEach((b) => b.classList.toggle("is-active", b.dataset.platformTab === platformKey));
      panels.forEach((p) => {
        p.hidden = p.dataset.platform !== platformKey;
      });
    }

    tabButtons.forEach((btn) => {
      btn.addEventListener("click", () => activate(btn.dataset.platformTab));
    });

    if (tabButtons.length) {
      activate(tabButtons[0].dataset.platformTab);
    }
  });

  // ------------------------------------------------------------------
  // Running a scrape
  // ------------------------------------------------------------------
  document.querySelectorAll(".run-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const platform = form.dataset.platform;
      const panel = form.closest(".panel");
      const statusEl = panel.querySelector('[data-role="status"]');
      const resultsEl = panel.querySelector('[data-role="results"]');
      const tableHeadEl = panel.querySelector('[data-role="table-head"]');
      const tableBodyEl = panel.querySelector('[data-role="table-body"]');
      const exportBar = panel.querySelector('[data-role="export-bar"]');
      const runBtn = form.querySelector(".btn--run");

      const formData = new FormData(form);
      const body = {
        target: formData.get("target") || "",
        auth_token: formData.get("auth_token") || "",
        limit: formData.get("limit") || "",
      };

      runBtn.disabled = true;
      runBtn.textContent = "Scraping…";
      statusEl.className = "status is-pending";
      statusEl.textContent = "Running scraper — this blocks until it finishes and the browser session closes.";
      exportBar.hidden = true;

      try {
        const response = await fetch(`/api/scrape/${platform}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const payload = await response.json();

        if (!response.ok || !payload.ok) {
          throw new Error(payload.error || `Request failed (${response.status})`);
        }

        statusEl.className = "status is-success";
        statusEl.textContent = `Done — pulled ${payload.count} item${payload.count === 1 ? "" : "s"} from ${payload.label}.`;

        if (tableBodyEl) {
          renderTable(tableHeadEl, tableBodyEl, payload.records);
        } else {
          renderResults(resultsEl, payload.rows, platform);
        }

        if (payload.count > 0) {
          const countEl = panel.querySelector('[data-role="export-count"]');
          countEl.textContent = `${payload.count} item${payload.count === 1 ? "" : "s"} ready to export`;
          exportBar.hidden = false;
        }
      } catch (err) {
        statusEl.className = "status is-error";
        statusEl.textContent = err.message || "Scrape failed. Check the terminal running the app for details.";
      } finally {
        runBtn.disabled = false;
        runBtn.textContent = "Run scrape";
      }
    });
  });

  // Trending Malware: renders whatever flat records a source's scraper
  // produced as a plain data table. Columns are read straight off the
  // data (union of every key seen, in first-appearance order) rather
  // than a fixed list, since ANY.RUN, Malpedia, and ThreatFox each use
  // different field names -- this is how every field from every source
  // ends up shown ("complete information as in each file") without
  // hardcoding three separate column sets. Any cell whose value is
  // itself an http(s) URL is rendered as a clickable link to that
  // record's page on the source site, rather than relying on a fixed
  // "this column is the link" name -- these scrapers have already
  // renamed their link field more than once between updates (ANY.RUN
  // alone has used record_link, then trend_url + report_url), so
  // detecting by content instead of column name survives that.
  function collectColumns(records) {
    const columns = [];
    records.forEach((record) => {
      Object.keys(record).forEach((key) => {
        if (!columns.includes(key)) columns.push(key);
      });
    });
    return columns;
  }

  function prettifyColumn(key) {
    const labels = {
      record_number: "#",
      malware_name: "Malware name (family)",
      os: "OS",
      operating_system: "OS",
      type: "Type",
      status: "Status",
      last_dated: "Last dated",
      word_rank: "Word rank",
      record_link: "Link",
      link: "Link",
      trend_url: "Trend page",
      report_url: "Sample report",
      tags: "Tags",
      reporter: "Reporter",
      ioc: "IOC",
    };
    if (labels[key]) return labels[key];
    return key
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function isUrl(value) {
    return typeof value === "string" && /^https?:\/\//i.test(value);
  }

  function renderTable(thead, tbody, records) {
    thead.innerHTML = "";
    tbody.innerHTML = "";

    if (!records || records.length === 0) {
      const tr = document.createElement("tr");
      tr.className = "empty-row";
      const td = document.createElement("td");
      td.colSpan = 99;
      td.textContent = "Scraper ran but returned no records. The site layout may have changed.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const columns = collectColumns(records);

    const headRow = document.createElement("tr");
    columns.forEach((col) => {
      const th = document.createElement("th");
      th.textContent = prettifyColumn(col);
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);

    records.forEach((record) => {
      const tr = document.createElement("tr");
      columns.forEach((col) => {
        const td = document.createElement("td");
        const value = record[col];
        const isEmpty = value === null || value === undefined || value === "";

        if (isUrl(value)) {
          const link = document.createElement("a");
          link.href = value;
          link.target = "_blank";
          link.rel = "noopener";
          link.className = "data-table__link";
          link.textContent = "Open ↗";
          td.appendChild(link);
        } else if (Array.isArray(value)) {
          td.textContent = value.length ? value.join(", ") : "—";
          if (!value.length) td.className = "data-table__empty-cell";
        } else {
          td.textContent = isEmpty ? "—" : value;
          if (isEmpty) td.className = "data-table__empty-cell";
        }

        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  function renderResults(container, rows, platform) {
    container.innerHTML = "";

    if (!rows || rows.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.innerHTML = "<p>Scraper ran but returned no items.</p><p class=\"empty-state__sub\">The site layout may have changed, or there was nothing new to find.</p>";
      container.appendChild(empty);
      return;
    }

    rows.forEach((row) => {
      const node = rowTemplate.content.cloneNode(true);

      const accountEl = node.querySelector(".result-card__account");
      const titleEl = node.querySelector(".result-card__title");
      const metaEl = node.querySelector(".result-card__meta");
      const descEl = node.querySelector(".result-card__desc");
      const iocsEl = node.querySelector(".result-card__iocs");
      const linkEl = node.querySelector(".result-card__link");

      accountEl.textContent = row.account || row.author || "";
      titleEl.textContent = row.title || truncate(row.body, 90) || "(untitled)";
      metaEl.textContent = [row.published, row.post_type].filter(Boolean).join(" · ");
      descEl.textContent = row.description || truncate(row.body, 220);

      renderIocs(iocsEl, row.iocs);

      if (row.url) {
        linkEl.href = row.url;
      } else {
        linkEl.remove();
      }

      container.appendChild(node);
    });
  }

  // Renders every IOC value for a row, grouped by type -- not just a
  // count badge. Each group is a labeled list of the actual indicators
  // (IPs, domains, hashes, CVEs, ...) so an analyst can read/copy them
  // without hovering to find a tooltip.
  function renderIocs(container, iocs) {
    container.innerHTML = "";

    const entries = Object.entries(iocs || {}).filter(([, v]) => Array.isArray(v) && v.length);

    if (!entries.length) {
      const none = document.createElement("span");
      none.className = "ioc-chip ioc-chip--none";
      none.textContent = "no IOCs found";
      container.appendChild(none);
      return;
    }

    entries.forEach(([type, values]) => {
      const group = document.createElement("div");
      group.className = "ioc-group";

      const label = document.createElement("span");
      label.className = "ioc-group__label";
      label.textContent = `${formatIocType(type)} (${values.length})`;
      group.appendChild(label);

      const list = document.createElement("div");
      list.className = "ioc-group__values";
      values.forEach((value) => {
        const item = document.createElement("code");
        item.className = "ioc-value";
        item.textContent = value;
        item.title = "Click to copy";
        item.addEventListener("click", () => copyToClipboard(value, item));
        list.appendChild(item);
      });
      group.appendChild(list);

      container.appendChild(group);
    });
  }

  function formatIocType(type) {
    const labels = {
      ipv4: "IPv4",
      defanged_ip: "IPv4 (defanged)",
      domains: "Domains",
      domain: "Domains",
      defanged_domain: "Domains (defanged)",
      urls: "URLs",
      url: "URLs",
      emails: "Emails",
      email: "Emails",
      md5: "MD5",
      sha1: "SHA1",
      sha256: "SHA256",
      sha512: "SHA512",
      cves: "CVEs",
      cve: "CVEs",
      mitre_attack: "MITRE ATT&CK",
      file_names: "File names",
      registry_paths: "Registry paths",
      windows_paths: "Windows paths",
      unix_paths: "Unix paths",
      bitcoin_addresses: "Bitcoin addresses",
      ipv6: "IPv6",
    };
    return labels[type] || type;
  }

  function copyToClipboard(text, el) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(() => {
      const original = el.classList.contains("ioc-value--copied");
      el.classList.add("ioc-value--copied");
      window.setTimeout(() => {
        if (!original) el.classList.remove("ioc-value--copied");
      }, 900);
    });
  }

  function truncate(text, length) {
    if (!text) return "";
    const clean = text.trim();
    if (clean.length <= length) return clean;
    return clean.slice(0, length).trim() + "…";
  }
})();
