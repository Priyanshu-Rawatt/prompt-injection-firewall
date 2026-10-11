package com.et.hackathon.firewall.repository;

import com.et.hackathon.firewall.entity.InspectionEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InspectionEventRepository extends JpaRepository<InspectionEvent, String> {
}
