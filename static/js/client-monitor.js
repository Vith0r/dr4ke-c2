document.addEventListener('DOMContentLoaded', () => {
    if (!window.Auth || !window.Auth.isAuthenticated()) return
  
    const style = document.createElement('style')
    style.textContent = `
      .tab-button { color:#94a3b8; position:relative; transition:all .3s }
      .tab-button:hover { color:#fff }
      .tab-active { color:#fff; border-bottom:2px solid #3b82f6 }
      input[type=checkbox] {
        appearance:none; -webkit-appearance:none; width:18px; height:18px;
        background:rgba(31,41,55,.5); border:1px solid rgba(255,255,255,.15);
        border-radius:4px; cursor:pointer; display:inline-flex;
        align-items:center; justify-content:center; transition:all .2s
      }
      input[type=checkbox]:checked {
        background:#3b82f6; border-color:#3b82f6
      }
      input[type=checkbox]:checked::after {
        content:'✓'; color:#fff; font-size:12px
      }
      input[type=checkbox]:focus {
        outline:2px solid rgba(59,130,246,.5)
      }
    `
    document.head.appendChild(style)
  
    function initClientStatusChart() {
      if (typeof Chart === 'undefined') return
      const c = document.getElementById('client-status-chart')
      if (!c) return
      new Chart(c, {
        type:'doughnut',
        data:{
          labels:['Active','Idle','Dead'],
          datasets:[{
            data:[0,0,0],
            backgroundColor:[
              'rgba(16,185,129,.8)',
              'rgba(245,158,11,.8)',
              'rgba(239,68,68,.8)'
            ],
            borderColor:[
              'rgba(16,185,129,1)',
              'rgba(245,158,11,1)',
              'rgba(239,68,68,1)'
            ],
            borderWidth:1
          }]
        },
        options:{
          responsive:true,
          maintainAspectRatio:false,
          cutout:'70%',
          plugins:{
            legend:{
              position:'bottom',
              labels:{
                color:'#fff',
                font:{family:'Inter',size:12}
              }
            }
          }
        }
      })
    }
  
    function initVisualEnhancements() {
      document.querySelectorAll('[id$="-count"]').forEach(el => {
        if (!el.textContent.includes('0')) el.classList.add('animate-pulse')
      })
    }
  
    function initAdditionalFeatures() {
      document.addEventListener('keydown', e => {
        if (e.ctrlKey && e.key === 'a' && document.activeElement.id !== 'commandInput') {
          e.preventDefault()
          document.getElementById('selectAllBtn')?.click()
        }
        if (e.key === 'Escape') document.getElementById('selectNoneBtn')?.click()
        if (e.ctrlKey && e.key === 'l') {
          e.preventDefault()
          document.getElementById('logout-btn')?.click()
        }
      })
  
      document.addEventListener('click', e => {
        const t = e.target.closest('[data-copy-id]')
        if (!t) return
        const id = t.getAttribute('data-copy-id')
        navigator.clipboard.writeText(id).then(() => {
          const toast = document.createElement('div')
          toast.className = 'fixed bottom-4 right-4 bg-green-500 text-white px-4 py-2 rounded shadow-lg z-50'
          toast.textContent = 'Client ID copied!'
          toast.style.opacity = '0'
          toast.style.transition = 'opacity .3s ease'
          document.body.appendChild(toast)
          setTimeout(() => (toast.style.opacity = '1'), 10)
          setTimeout(() => {
            toast.style.opacity = '0'
            setTimeout(() => document.body.removeChild(toast), 300)
          }, 2000)
        })
      })
    }
  
    initClientStatusChart()
    initVisualEnhancements()
    initAdditionalFeatures()
  })
  