document.addEventListener('DOMContentLoaded', () => {
    const navbar = document.querySelector('.navbar');
    const backToTopButton = document.querySelector('.back-to-top');
    const moonIcon = document.getElementById('moon-icon');
    const sunIcon = document.getElementById('sun-icon');

    // Function to update dark mode icons
    const updateIcons = () => {
        if (document.body.classList.contains('dark-mode')) {
            moonIcon.classList.remove('d-none');
            sunIcon.classList.add('d-none');
        } else {
            moonIcon.classList.add('d-none');
            sunIcon.classList.remove('d-none');
        }
    };

    // Dark mode toggle
    window.toggleDarkMode = function() {
        document.body.classList.toggle("dark-mode");
        if (document.body.classList.contains('dark-mode')) {
            localStorage.setItem('theme', 'dark');
        } else {
            localStorage.setItem('theme', 'light');
        }
        updateIcons();
    }

    // Check for saved theme preference
    if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark-mode');
    }
    updateIcons();


    // Navbar scroll effect
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
        // Back to top button visibility
        if (window.scrollY > 300) {
            backToTopButton.classList.add('visible');
        } else {
            backToTopButton.classList.remove('visible');
        }
    });

    // Animate on scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1
    });

    document.querySelectorAll('.feature-card, .team-member, .use-case-card, .testimonial-card').forEach(el => {
        observer.observe(el);
    });

     // Back to top button click
     backToTopButton.addEventListener('click', (e) => {
        e.preventDefault();
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });

});

// Loader animation
window.addEventListener("load", function () {
    const spinner = document.querySelector(".spinner-wrapper");
    spinner.style.opacity = '0';
    setTimeout(() => {
        spinner.style.display = "none";
    }, 500);
});