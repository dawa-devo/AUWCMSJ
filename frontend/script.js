document.addEventListener('DOMContentLoaded', () => {
    // 1. Button 'Next' hundaaf
    const nextButtons = document.querySelectorAll('.btn-next');
    nextButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            // Fuula itti aanu murteessuuf (filename irratti hundaa'uun)
            const currentFile = window.location.pathname.split("/").pop();
            
            if (currentFile === "register.html") window.location.href = "fcontact.html";
            else if (currentFile === "fcontact.html") window.location.href = "password.html";
        });
    });

    // 2. Button 'Previous' hundaaf
    const prevButtons = document.querySelectorAll('.btn-prev');
    prevButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            window.history.back();
        });
    });

    // 3. Fuula Password irratti validation erga xumuramee booda
    const passwordForm = document.getElementById('passwordForm');
    if (passwordForm) {
        passwordForm.addEventListener('submit', (e) => {
            // Bakka kanaa koodii validation password isa ati qabdu jira
            // Erga mirkanaa'ee booda gara skill.html deema
            window.location.href = "skill.html";
        });
    }

    // 4. Fuula Skill irratti submit yoo godhu
    const skillsForm = document.getElementById('skillsForm');
    if (skillsForm) {
        skillsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            window.location.href = "verification.html";
        });
    }
});