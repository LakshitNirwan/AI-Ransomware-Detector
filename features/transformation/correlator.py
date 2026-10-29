from dataclasses import dataclass
from typing import List
from .analyzer import TransformationEvidence

@dataclass(frozen=True)
class ProcessTransformationEvidence:
    pid:int
    observation_window_seconds:float
    files_observed:int
    files_transformed:int
    files_created:int
    files_modified:int
    files_renamed:int
    files_deleted:int
    content_changed_count:int
    size_changed_count:int
    extension_changed_count:int
    destructive_transformations:int
    transformation_rate:float
    transformation_consistency:float
    def to_dict(self): return {k:getattr(self,k) for k in self.__dataclass_fields__}

class ProcessTransformationCorrelator:
    def __init__(self,pid:int,observation_window_seconds:float):
        if pid<=0: raise ValueError("PID must be positive")
        if observation_window_seconds<=0: raise ValueError("Observation window must be positive")
        self.pid=pid; self.observation_window_seconds=observation_window_seconds
        self._evidence:List[TransformationEvidence]=[]
    def add(self,evidence):
        if evidence.pid!=self.pid: raise ValueError("Evidence PID does not match correlator PID")
        self._evidence.append(evidence)
    def summarize(self):
        e=self._evidence
        changed=[x.content_changed or x.size_changed or x.extension_changed or x.renamed or x.deleted for x in e]
        n=len(e); transformed=sum(changed)
        return ProcessTransformationEvidence(self.pid,self.observation_window_seconds,n,transformed,0,
            sum(x.content_changed or x.size_changed for x in e),sum(x.renamed for x in e),sum(x.deleted for x in e),
            sum(x.content_changed for x in e),sum(x.size_changed for x in e),sum(x.extension_changed for x in e),
            sum(x.deleted or x.renamed for x in e),transformed/self.observation_window_seconds,
            transformed/n if n else 0.0)
