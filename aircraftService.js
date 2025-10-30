import { WebSocketServer } from 'ws';

class AircraftService {
    constructor() {
        this.aircraftData = new Map();
        this.wss = null;
        this.cleanupInterval = null;
    }

    initialize(server) {
        this.wss = new WebSocketServer({ 
            server: server,
            path: '/ws/aircraft'
        });

        this.startCleanupInterval();
        this.setupWebSocketHandlers();
        
        console.log('Aircraft tracking service initialized');
    }

    startCleanupInterval() {
        this.cleanupInterval = setInterval(() => {
            const now = Date.now() / 1000;
            let removedCount = 0;
            
            for (const [id, aircraft] of this.aircraftData.entries()) {
                if (now - aircraft.timestamp > 30) {
                    this.aircraftData.delete(id);
                    this.broadcast({ type: 'aircraft_removed', id });
                    removedCount++;
                }
            }
            
            if (removedCount > 0) {
                console.log(`Cleaned up ${removedCount} inactive aircraft`);
            }
        }, 10000);
    }

    setupWebSocketHandlers() {
        this.wss.on('connection', (ws, req) => {
            console.log('Aircraft tracking client connected from:', req.socket.remoteAddress);
            
            // Send current aircraft data to new client
            ws.send(JSON.stringify({
                type: 'initial_data',
                aircraft: Array.from(this.aircraftData.values()),
                timestamp: Date.now()
            }));
            
            ws.on('close', () => {
                console.log('Aircraft tracking client disconnected');
            });

            ws.on('error', (error) => {
                console.error('WebSocket error:', error);
            });
        });

        this.wss.on('error', (error) => {
            console.error('WebSocket server error:', error);
        });
    }

    broadcast(data) {
        if (this.wss) {
            const message = JSON.stringify({
                ...data,
                timestamp: Date.now()
            });

            this.wss.clients.forEach(client => {
                if (client.readyState === 1) { // WebSocket.OPEN
                    try {
                        client.send(message);
                    } catch (error) {
                        console.error('Error broadcasting to client:', error);
                    }
                }
            });
        }
    }

    updateAircraft(aircraftArray) {
        if (!Array.isArray(aircraftArray)) {
            throw new Error('Expected array of aircraft');
        }

        // Validate and update aircraft data
        const validatedAircraft = [];
        
        for (const aircraft of aircraftArray) {
            // Basic validation
            if (this.isValidAircraft(aircraft)) {
                aircraft.timestamp = Date.now() / 1000;
                this.aircraftData.set(aircraft.id, aircraft);
                validatedAircraft.push(aircraft);
            } else {
                console.warn('Invalid aircraft data received:', aircraft);
            }
        }

        if (validatedAircraft.length > 0) {
            this.broadcast({
                type: 'aircraft_update',
                aircraft: validatedAircraft
            });
        }

        return {
            success: true,
            updated: validatedAircraft.length,
            total: this.aircraftData.size,
            connectedClients: this.wss ? this.wss.clients.size : 0
        };
    }

    isValidAircraft(aircraft) {
        return true;
    }

    getAllAircraft() {
        return Array.from(this.aircraftData.values());
    }

    getAircraftCount() {
        return this.aircraftData.size;
    }

    getConnectedClientsCount() {
        return this.wss ? this.wss.clients.size : 0;
    }

    shutdown() {
        console.log('Shutting down aircraft service...');
        
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        
        if (this.wss) {
            // Notify all clients of shutdown
            this.broadcast({ type: 'server_shutdown' });
            
            // Close all connections
            this.wss.clients.forEach(client => {
                client.close(1001, 'Server shutting down');
            });
            
            this.wss.close();
        }
        
        this.aircraftData.clear();
        console.log('Aircraft service shutdown complete');
    }
}

export default new AircraftService();
