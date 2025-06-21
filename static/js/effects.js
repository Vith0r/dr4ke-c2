document.addEventListener('DOMContentLoaded', function() {
    setTimeout(() => {
        AOS.init({
            once: true,
            disable: window.innerWidth < 768
        })
    }, 100)
    initparticles()
    addripple()
})

function initparticles() {
    const container = document.querySelector('.particles-container')
    if (!container) return
    const count = 30
    for (let i = 0; i < count; i++) {
        const p = document.createElement('div')
        p.className = 'particle'
        const x = Math.random() * 100
        const y = Math.random() * 100
        const size = Math.random() * 6 + 1
        const opacity = Math.random() * 0.5 + 0.1
        const duration = Math.random() * 20 + 10
        p.style.left = `${x}%`
        p.style.top = `${y}%`
        p.style.width = `${size}px`
        p.style.height = `${size}px`
        p.style.opacity = opacity
        p.style.animationDuration = `${duration}s`
        container.appendChild(p)
    }
}

function addripple() {
    const els = document.querySelectorAll('.neo-btn, .neo-btn-primary, .tab-button, button')
    els.forEach(el => el.classList.add('ripple'))
}
