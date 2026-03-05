import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Brain, Code2, Shield, FileCode } from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { api } from '../services/api';
import { toast } from 'sonner';

const AIKnowledgeBase = () => {
  const [debugRecords, setDebugRecords] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDebugRecords();
  }, []);

  const fetchDebugRecords = async () => {
    try {
      const data = await api.getAIDebug();
      setDebugRecords(data);
    } catch (error) {
      toast.error('Failed to load AI debug data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center min-h-[60vh]">
          <div className="animate-spin w-12 h-12 border-4 border-primary border-t-transparent rounded-full" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-8" data-testid="ai-knowledge-base">
        <div>
          <h1 className="text-4xl font-bold mb-2">AI Knowledge Base</h1>
          <p className="text-muted-foreground text-lg">
            Full pipeline debug data from Wrapper Hunter &rarr; LLM &rarr; Semgrep rules
          </p>
        </div>

        <div className="space-y-4">
          {debugRecords.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Brain className="w-16 h-16 mx-auto mb-4 opacity-50 text-muted-foreground" />
                <p className="text-lg text-muted-foreground">No AI debug records yet</p>
                <p className="text-sm text-muted-foreground mt-2">
                  Scan your repositories to generate AI analysis data
                </p>
              </CardContent>
            </Card>
          ) : (
            debugRecords.map((record, index) => (
              <motion.div
                key={record.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
              >
                <Card className="hover:border-primary/30 transition-all" data-testid={`debug-record-${index}`}>
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <CardTitle className="text-lg">
                            {record.repository_name || record.repository_id}
                          </CardTitle>
                          <Badge variant="outline" className="font-mono text-xs">
                            {record.scan_id?.slice(0, 8)}
                          </Badge>
                        </div>
                        <CardDescription>
                          {new Date(record.created_at).toLocaleString()}
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-yellow-500" />
                        <span className="text-muted-foreground">Vulnerable wrappers:</span>
                        <span className="font-semibold text-primary">{record.vuln_wrapper_count ?? 0}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Code2 className="w-4 h-4 text-blue-500" />
                        <span className="text-muted-foreground">Sink modules:</span>
                        <span className="font-semibold text-primary">{record.sink_module_count ?? 0}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <FileCode className="w-4 h-4 text-green-500" />
                        <span className="text-muted-foreground">Semgrep rules:</span>
                        <span className="font-semibold text-primary">{record.rules_count ?? 0}</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AIKnowledgeBase;
