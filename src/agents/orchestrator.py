"""
Orchestrator - Coordinates everything
"""
from alert_agent import AlertAgent
from response_agent import ResponseAgent

class ResponseOrchestrator:
    def __init__(self, config):
        self.alert_agent = AlertAgent(config)
        self.response_agent = ResponseAgent(config)
        
        # Start alert background processor
        self.alert_agent.start()
        print("✅ Alert agent running in background")
        print("✅ Response agent ready for immediate action")
    
    def handle_threat(self, detection_result, expert_analysis):
        """
        This is the main function - called when threat detected
        """
        print(f"\n🚨 THREAT DETECTED: {detection_result['attack_type']}")
        
        # STEP 1: Generate alert (fast, just creates object)
        alert = self.alert_agent.generate_alert(detection_result, expert_analysis)
        
        # STEP 2: Queue alert for background sending (NON-BLOCKING)
        self.alert_agent.queue_alert(alert)
        print("📧 Alert queued - will send in background")
        
        # STEP 3: Check if we need to respond (IMMEDIATE)
        if self.response_agent.should_respond(alert, expert_analysis):
            print("⚡ Taking immediate action based on expert advice...")
            
            # This happens NOW while alerts send in background
            response = self.response_agent.execute_response(alert, expert_analysis)
            
            print(f"✅ Actions taken: {len(response['actions'])}")
            return response
        else:
            print("ℹ️ No automated response needed")
            return None
    
    def shutdown(self):
        """Clean shutdown"""
        self.alert_agent.stop()