# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
This module contains functions for periodical cleaning up after an offer is expired
"""

import datetime
import threading
import logging
from typing import Generator
import contextlib
import common.config
import common.db.postgres as db

import issuer.db.credential as db_cred


@contextlib.contextmanager
def midnight_cleanup_lifespan() -> contextlib.AbstractContextManager:
    """
    Lifespan managing a midnight cleanup timer.
    Runs once immediatly after creating to achieve a clean state.
    """
    timeout_manager = MidnightCleanupTimer()
    timeout_manager.set_immediate_timer()
    yield
    timeout_manager.cancel_timer()


class MidnightCleanupTimer:
    """Timer, once started will run every midnight, rescheduling itself afterwards"""

    _timer: threading.Timer = None

    def __init__(self, session_function: Generator[db.Session, None, None] = db.env_session) -> None:
        """* session_function: a generator to call using contextlib to get a session."""
        # FastAPI does something similar internally, to use the same function
        # we have to create the context manager from the generator
        self._session_function = contextlib.contextmanager(session_function)

    def _next_trigger_seconds(self) -> float:
        """Calculate the remaining seconds"""
        next_calendar_day = datetime.date.today() + datetime.timedelta(days=1)
        next_midnight = datetime.datetime.combine(
            next_calendar_day,
            datetime.datetime.min.time(),
        )
        time_to_midnight = next_midnight - datetime.datetime.today()
        return time_to_midnight.total_seconds()

    def _delete_expired_offer_data(self) -> None:
        """
        Deletes the expired offer data and logs each expired management_id & the total of expired offers.
        Starts a new timer
        """
        with self._session_function(common.config.DBConfig()) as session:
            expired_offers = db_cred.get_new_expired_offers(session)
            # Expire offers
            [offer.validity_check() for offer in expired_offers]
            logging.info(f"Expired total of {len(expired_offers)} credential offers today")
            session.flush()
            session.commit()
            self.set_midnight_timer()

    def set_timer(self, time: float):
        """Starts the timer scheduled to next midnight. Cancels other instances of the timer"""
        self.cancel_timer()
        logging.info(f"Next cleanup {time=}")
        self._timer = threading.Timer(time, self._delete_expired_offer_data)
        self._timer.start()

    def set_midnight_timer(self):
        """Sets the timer for next midnight."""
        seconds_until_next_trigger = self._next_trigger_seconds()
        self.set_timer(seconds_until_next_trigger)

    def set_immediate_timer(self):
        """Runs the action of the timer immediatly. Reschedules it after normally"""
        self.set_timer(1)

    def cancel_timer(self):
        """Stops the timer thread."""
        if self._timer:
            self._timer.cancel()
