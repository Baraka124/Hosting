<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>COPD Digital Tracing Dashboard</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f5f7fa;
      margin: 0;
      padding: 2rem;
      color: #333;
    }
    h1 {
      color: #2b4eff;
      text-align: center;
    }
    #patients {
      margin-top: 2rem;
      border-collapse: collapse;
      width: 100%;
    }
    #patients th, #patients td {
      border: 1px solid #ccc;
      padding: 8px;
      text-align: left;
    }
    #patients th {
      background-color: #e8ecff;
    }
    form {
      margin-bottom: 2rem;
      background: white;
      padding: 1rem;
      border-radius: 10px;
      box-shadow: 0 0 5px rgba(0,0,0,0.1);
    }
    input, select {
      padding: 0.4rem;
      margin-right: 0.5rem;
    }
    button {
      background: #2b4eff;
      color: white;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 5px;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <h1>COPD Digital Tracing Dashboard</h1>

  <form id="addPatientForm">
    <input type="text" id="name" placeholder="Name" required>
    <input type="number" id="age" placeholder="Age">
    <select id="gender">
      <option value="">Gender</option>
      <option value="Male">Male</option>
      <option value="Female">Female</option>
    </select>
    <button type="submit">Add Patient</button>
  </form>

  <table id="patients">
    <thead>
      <tr>
        <th>ID</th><th>Name</th><th>Age</th><th>Gender</th><th>Diagnosis Date</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

  <script>
    // Replace with your backend URL:
    const API_BASE = "https://hosting-production-a352.up.railway.app/api";

    async function loadPatients() {
      try {
        const res = await fetch(`${API_BASE}/patients`);
        if (!res.ok) throw new Error('Response not OK');
        const patients = await res.json();

        const tbody = document.querySelector("#patients tbody");
        tbody.innerHTML = "";
        patients.forEach(p => {
          const row = `<tr>
            <td>${p.id}</td>
            <td>${p.name}</td>
            <td>${p.age ?? '-'}</td>
            <td>${p.gender ?? '-'}</td>
            <td>${p.diagnosis_date ?? '-'}</td>
          </tr>`;
          tbody.innerHTML += row;
        });
      } catch (err) {
        console.error(err);
        alert("Unable to load data. Check backend URL or /api/patients route.");
      }
    }

    document.querySelector("#addPatientForm").addEventListener("submit", async e => {
      e.preventDefault();
      const name = document.querySelector("#name").value.trim();
      const age = document.querySelector("#age").value;
      const gender = document.querySelector("#gender").value;
      if (!name) return alert("Please enter a name");

      await fetch(`${API_BASE}/patients`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ name, age, gender })
      });

      document.querySelector("#name").value = "";
      document.querySelector("#age").value = "";
      document.querySelector("#gender").value = "";
      loadPatients();
    });

    loadPatients();
  </script>
</body>
</html>
