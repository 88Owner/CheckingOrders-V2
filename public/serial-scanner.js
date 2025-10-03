/**
 * Serial Scanner Module - Đọc dữ liệu từ máy quét COM port
 * Sử dụng Web Serial API
 */

class SerialScanner {
    constructor() {
        this.port = null;
        this.reader = null;
        this.isReading = false;
        this.buffer = '';
        this.onScanCallback = null;
    }

    /**
     * Kiểm tra browser có hỗ trợ Web Serial API không
     */
    isSupported() {
        return 'serial' in navigator;
    }

    /**
     * Yêu cầu user chọn COM port
     */
    async requestPort() {
        try {
            if (!this.isSupported()) {
                throw new Error('Trình duyệt không hỗ trợ Web Serial API. Vui lòng dùng Chrome, Edge hoặc Opera.');
            }

            // Yêu cầu user chọn port
            this.port = await navigator.serial.requestPort();
            console.log('✅ Đã chọn COM port:', this.port);
            return true;
        } catch (error) {
            console.error('❌ Lỗi chọn COM port:', error);
            throw error;
        }
    }

    /**
     * Kết nối tới COM port
     */
    async connect(baudRate = 9600) {
        try {
            if (!this.port) {
                throw new Error('Chưa chọn COM port. Hãy gọi requestPort() trước.');
            }

            // Mở port với cấu hình
            await this.port.open({ 
                baudRate: baudRate,
                dataBits: 8,
                stopBits: 1,
                parity: 'none',
                flowControl: 'none'
            });

            console.log('✅ Đã kết nối tới COM port');
            return true;
        } catch (error) {
            console.error('❌ Lỗi kết nối COM port:', error);
            throw error;
        }
    }

    /**
     * Bắt đầu đọc dữ liệu từ COM port
     */
    startReading(onScan) {
        if (!this.port || !this.port.readable) {
            throw new Error('COM port chưa được mở');
        }

        this.onScanCallback = onScan;
        this.isReading = true;
        this.buffer = '';

        console.log('✅ Bắt đầu đọc dữ liệu từ COM port...');

        // Chạy đọc dữ liệu trong background (không block)
        this._readLoop();
    }

    /**
     * Loop đọc dữ liệu (chạy trong background)
     */
    async _readLoop() {
        try {
            const textDecoder = new TextDecoderStream();
            const readableStreamClosed = this.port.readable.pipeTo(textDecoder.writable);
            this.reader = textDecoder.readable.getReader();

            // Đọc dữ liệu liên tục
            while (this.isReading) {
                const { value, done } = await this.reader.read();
                
                if (done) {
                    console.log('📡 Reader đã đóng');
                    this.reader.releaseLock();
                    break;
                }

                if (value) {
                    // Thêm dữ liệu vào buffer
                    this.buffer += value;
                    console.log('📥 Nhận dữ liệu từ COM:', value, '(buffer:', this.buffer, ')');

                    // Kiểm tra ký tự kết thúc (thường là \r\n hoặc \n)
                    if (this.buffer.includes('\n') || this.buffer.includes('\r')) {
                        // Lấy dữ liệu hoàn chỉnh
                        const scannedData = this.buffer
                            .trim()
                            .replace(/[\r\n]+/g, ''); // Loại bỏ \r\n

                        if (scannedData) {
                            console.log('✅ Quét thành công:', scannedData);
                            
                            // Gọi callback
                            if (this.onScanCallback) {
                                try {
                                    this.onScanCallback(scannedData);
                                } catch (callbackError) {
                                    console.error('❌ Lỗi trong callback:', callbackError);
                                }
                            }
                        }

                        // Reset buffer
                        this.buffer = '';
                    }
                }
            }

            await readableStreamClosed.catch(() => {}); // Ignore close errors
        } catch (error) {
            console.error('❌ Lỗi đọc dữ liệu:', error);
            console.error('Stack:', error.stack);
        }
    }

    /**
     * Dừng đọc dữ liệu
     */
    async stopReading() {
        this.isReading = false;
        
        if (this.reader) {
            try {
                await this.reader.cancel();
                this.reader.releaseLock();
                console.log('✅ Đã dừng đọc dữ liệu');
            } catch (error) {
                console.error('❌ Lỗi dừng reader:', error);
            }
        }
    }

    /**
     * Ngắt kết nối COM port
     */
    async disconnect() {
        await this.stopReading();
        
        if (this.port) {
            try {
                await this.port.close();
                this.port = null;
                console.log('✅ Đã ngắt kết nối COM port');
            } catch (error) {
                console.error('❌ Lỗi đóng port:', error);
            }
        }
    }

    /**
     * Lấy danh sách các port đã được cấp quyền
     */
    async getAvailablePorts() {
        try {
            const ports = await navigator.serial.getPorts();
            console.log('📡 Các port khả dụng:', ports);
            return ports;
        } catch (error) {
            console.error('❌ Lỗi lấy danh sách port:', error);
            return [];
        }
    }

    /**
     * Kết nối tự động với port đã lưu (nếu có)
     */
    async connectToSavedPort(baudRate = 9600) {
        try {
            const ports = await this.getAvailablePorts();
            
            if (ports.length === 0) {
                console.log('⚠️  Không có port nào được cấp quyền trước đó');
                return false;
            }

            // Sử dụng port đầu tiên
            this.port = ports[0];
            await this.connect(baudRate);
            return true;
        } catch (error) {
            console.error('❌ Lỗi kết nối tự động:', error);
            return false;
        }
    }
}

// Export để sử dụng trong các file khác
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SerialScanner;
} 