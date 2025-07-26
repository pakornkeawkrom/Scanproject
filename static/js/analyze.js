document.addEventListener('DOMContentLoaded', function () {
    // === Elements for Code Analysis ===
    const analyzeButton = document.getElementById('analyze-button');
    const codeInput = document.getElementById('code-input');
    const loadingMessage = document.getElementById('loading-message');
    const errorMessage = document.getElementById('error-message');
    const resultsContainer = document.getElementById('results-container');
    const scanInputArea = document.getElementById('scan-input-area');

    // ✅ INITIALIZATION CHECK for Core Elements
    if (!analyzeButton || !codeInput || !loadingMessage || !errorMessage || !resultsContainer || !scanInputArea) {
        console.error("Initialization Error: One or more core HTML elements for analysis not found.");
        // We can still proceed if only history elements are missing, but core functions won't work.
        // For history, we'll check existence before adding listeners.
    } else {
        console.info("analyze.js: Core script elements initialized successfully.");
    }

    // === Elements for History Management ===
    const deleteSelectedButton = document.getElementById('delete-selected-button');
    const clearAllForm = document.getElementById('clear-all-form'); 

    // === CSRF Token (Assuming Django setup) ===
    let csrftoken = '';
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfInput = document.querySelector('input[name="csrfmiddlewaretoken"]'); 

    if (csrfMeta) {
        csrftoken = csrfMeta.getAttribute('content');
        console.log("CSRF token found from meta tag.");
    } else if (csrfInput) {
        csrftoken = csrfInput.value;
        console.log("CSRF token found from hidden input.");
    } else {
        console.error("CSRF token not found. Please ensure a meta tag (<meta name=\"csrf-token\" content=\"{{ csrf_token }}\">) or hidden input is available in your base.html or index.html.");
    }

    // === Helper Functions for Messages ===
    function showMessage(element, text, isError = false) {
        // Ensure all message elements exist before trying to modify them
        if (loadingMessage) loadingMessage.classList.add('hidden');
        if (errorMessage) errorMessage.classList.add('hidden');

        if (element) {
            element.textContent = text;
            element.classList.remove('hidden');

            if (isError) {
                element.classList.remove('loading-message');
                element.classList.add('error-message');
            } else {
                element.classList.remove('error-message');
                element.classList.add('loading-message');
            }
        }
        console.log(`Message shown: "${text}" (Error: ${isError})`);
    }

    function hideMessages() {
        if (loadingMessage) loadingMessage.classList.add('hidden');
        if (errorMessage) errorMessage.classList.add('hidden');
    }

    // === Event Listener for Analyze Button ===
    if (analyzeButton && codeInput && resultsContainer && scanInputArea) {
        analyzeButton.addEventListener('click', async function () {
            console.log("Analyze button clicked.");
            const code = codeInput.value.trim();

            hideMessages();
            resultsContainer.classList.add('hidden');
            resultsContainer.innerHTML = ''; // Clear previous results

            if (!code) {
                showMessage(errorMessage, 'กรุณาใส่โค้ดก่อนวิเคราะห์', true);
                return;
            }

            showMessage(loadingMessage, 'กำลังวิเคราะห์โค้ด...');
            analyzeButton.disabled = true;

            try {
                if (!csrftoken) {
                    throw new Error('CSRF token ไม่พบ ไม่สามารถส่งคำขอได้');
                }

                const response = await fetch('/analyze_code/', { // Double-check this URL against your urls.py
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrftoken
                    },
                    body: JSON.stringify({ code })
                });

                console.log("Response status for analyze_code:", response.status);

                if (!response.ok) {
                    let errorText = `HTTP error ${response.status}`;
                    if (response.headers.get('Content-Type')?.includes('application/json')) {
                        const errorData = await response.json();
                        errorText = errorData.error || errorText;
                    } else {
                        errorText = await response.text();
                    }
                    throw new Error(errorText);
                }

                const data = await response.json();
                if (data.html) {
                    resultsContainer.innerHTML = data.html;
                    resultsContainer.classList.remove('hidden');
                    scanInputArea.classList.add('hidden');
                    window.scrollTo({ top: resultsContainer.offsetTop - 50, behavior: 'smooth' });
                    
                    if (data.scan_id) {
                         const viewScanUrlBase = document.body.dataset.viewScanUrlBase;
                         if (viewScanUrlBase) {
                             history.pushState(null, '', viewScanUrlBase.replace('0', data.scan_id));
                             console.log("URL updated to view scan_id:", data.scan_id);
                         } else {
                             console.warn("data-view-scan-url-base not found on body. URL not updated.");
                         }
                    }

                } else {
                    showMessage(errorMessage, data.error || 'ไม่พบข้อมูล HTML จากเซิร์ฟเวอร์', true);
                }
            } catch (error) {
                console.error("Analysis error:", error);
                showMessage(errorMessage, `เกิดข้อผิดพลาด: ${error.message}`, true);
            } finally {
                hideMessages();
                analyzeButton.disabled = false;
                // Important: Update delete button state after new scan might affect history
                updateDeleteButtonState(); 
            }
        });
    }

    // === Initial Display Logic (on page load) ===
    // Checks if the page is loading to view a specific scan result (from Django context)
    // This assumes you set a data attribute on the body or a known element in Django template.
    // Example in Django template: <body data-is-viewing-scan="{% if scan_result %}true{% else %}false{% endif %}">
    const isViewingScanResult = document.body.dataset.isViewingScan === "true";

    if (scanInputArea && resultsContainer) { // Check if elements exist
        if (isViewingScanResult) {
            scanInputArea.classList.add('hidden');
            resultsContainer.classList.remove('hidden');
            console.log("Initial display: Viewing scan result, hiding input area.");
        } else {
            scanInputArea.classList.remove('hidden');
            resultsContainer.classList.add('hidden');
            console.log("Initial display: No scan result, showing input area.");
        }
    }


    // --- JavaScript for Delete Selected Items ---

    // Function to update the state of the delete selected button
    function updateDeleteButtonState() {
        if (!deleteSelectedButton) {
            console.warn("Delete selected button element not found. Cannot update its state.");
            return; 
        }

        const checkedCount = document.querySelectorAll('.history-checkbox:checked').length;
        console.log("Checked checkboxes count:", checkedCount);

        if (checkedCount > 0) {
            deleteSelectedButton.removeAttribute('disabled');
            console.log("Delete selected button enabled.");
        } else {
            deleteSelectedButton.setAttribute('disabled', 'disabled');
            console.log("Delete selected button disabled.");
        }
    }

    // Use Event Delegation for checkboxes to support dynamically added items
    // Listens for 'change' events on the document body and checks if the target is a history-checkbox
    document.body.addEventListener('change', function(event) {
        if (event.target && event.target.classList && event.target.classList.contains('history-checkbox')) {
            console.log("History checkbox state changed:", event.target.value, "Checked:", event.target.checked);
            updateDeleteButtonState();
        }
    });

    // Attach Event Listener for the 'Delete Selected' button
    if (deleteSelectedButton) { // Ensure the button exists before adding listener
        console.log("Delete selected button found. Attaching click listener.");
        deleteSelectedButton.addEventListener('click', function() {
            console.log("Delete Selected button clicked.");
            const selectedScanIds = [];
            // Re-query all checked checkboxes each time the button is clicked
            document.querySelectorAll('.history-checkbox:checked').forEach(checkbox => {
                selectedScanIds.push(checkbox.value);
            });

            console.log("Selected Scan IDs for deletion:", selectedScanIds);

            if (selectedScanIds.length === 0) {
                alert('โปรดเลือกรายการที่ต้องการลบ!');
                return;
            }

            if (confirm(`คุณแน่ใจหรือไม่ว่าต้องการลบ ${selectedScanIds.length} รายการที่เลือก? การกระทำนี้ไม่สามารถย้อนกลับได้!`)) {
                fetch('/delete_selected_scans/', { // Double-check this URL against your urls.py
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrftoken
                    },
                    body: JSON.stringify({ scan_ids: selectedScanIds })
                })
                .then(response => {
                    console.log("Delete selected scans response status:", response.status);
                    if (!response.ok) {
                        return response.json().then(error => {
                            throw new Error(error.message || `Server error: ${response.status}`);
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.status === 'success') {
                        alert(`ลบไปแล้ว ${data.deleted_count} รายการ.`);
                        location.reload(); // Reload the page to refresh the history list
                    } else {
                        alert('เกิดข้อผิดพลาดในการลบ: ' + data.message);
                    }
                })
                .catch(error => {
                    console.error('Error during delete selected scans request:', error);
                    alert('เกิดข้อผิดพลาดในการส่งคำขอลบ: ' + error.message);
                });
            }
        });
    } else {
        console.warn("Delete selected button not found. History deletion by selection will not work.");
    }

    // Optional: Add event listener for "back to scan" button (if it exists)
    const backToScanButton = document.querySelector('.back-to-scan');
    if (backToScanButton) {
        backToScanButton.addEventListener('click', function(event) {
            event.preventDefault(); // Prevent default link behavior
            if (scanInputArea) scanInputArea.classList.remove('hidden');
            if (resultsContainer) resultsContainer.classList.add('hidden');
            if (codeInput) codeInput.value = ''; // Clear the input area
            hideMessages();
            history.pushState(null, '', '/'); // Or the actual URL for your index page
        });
    }

    // Initial check for delete button state when the page loads
    updateDeleteButtonState();
    console.log("Initial updateDeleteButtonState called.");
});