(function () {
  const config = window.ROLE_SCREEN_CONFIG || {};
  const titleEl = document.getElementById("roleTitle");
  const subtitleEl = document.getElementById("roleSubtitle");
  const kpiEl = document.getElementById("kpiGrid");
  const tableBodyEl = document.getElementById("taskTableBody");
  const todoEl = document.getElementById("todoList");
  const activityEl = document.getElementById("activityList");
  const logoutBtn = document.getElementById("logoutBtn");

  if (titleEl) titleEl.textContent = config.title || "Màn hình vận hành";
  if (subtitleEl) subtitleEl.textContent = config.subtitle || "Theo dõi công việc theo vai trò";

  const kpis = config.kpis || [];
  kpiEl.innerHTML = kpis
    .map(
      (item) => `
        <div class="kpi-card">
          <div class="kpi-title">${item.label}</div>
          <div class="kpi-value">${item.value}</div>
          <div class="kpi-note">${item.note || ""}</div>
        </div>
      `
    )
    .join("");

  const tasks = config.tasks || [];
  tableBodyEl.innerHTML = tasks
    .map(
      (task) => `
        <tr>
          <td>${task.orderCode}</td>
          <td>${task.step}</td>
          <td>${task.owner}</td>
          <td>${task.due}</td>
          <td><span class="badge ${task.badgeClass || "info"}">${task.status}</span></td>
        </tr>
      `
    )
    .join("");

  const todos = config.todos || [];
  todoEl.innerHTML = todos.map((item) => `<li>${item}</li>`).join("");

  const activities = config.activities || [];
  activityEl.innerHTML = activities.map((item) => `<li>${item}</li>`).join("");

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async function () {
      try {
        await fetch("/api/logout", { method: "POST" });
      } catch (_) {
      } finally {
        window.location.href = "/login";
      }
    });
  }
})();
